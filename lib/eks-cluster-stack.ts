import * as cdk from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import {aws_ec2, CfnJson} from 'aws-cdk-lib';
import {
  FlowLogDestination,
  GatewayVpcEndpointAwsService,
  IVpc,
  Peer,
  Port,
  SecurityGroup,
  Vpc
} from 'aws-cdk-lib/aws-ec2';
import {
  AwsAuth,
  CfnAddon,
  Cluster,
  ClusterLoggingTypes,
  CoreDnsComputeType,
  EndpointAccess, KubernetesManifest,
  KubernetesVersion,
} from 'aws-cdk-lib/aws-eks';
import {
  AccountPrincipal,
  Effect,
  ManagedPolicy,
  OpenIdConnectPrincipal,
  PolicyStatement,
  Role,
  ServicePrincipal
} from 'aws-cdk-lib/aws-iam';
import {Key} from 'aws-cdk-lib/aws-kms';
import {KubectlV28Layer} from '@aws-cdk/lambda-layer-kubectl-v28';
import {Construct} from 'constructs';
import * as fs from "fs";
import {addEndpoint, eksVpc} from "./vpc-stack";
interface ekstackprops extends cdk.StackProps {}

export class Ekstack extends cdk.Stack {
  public readonly cluster: Cluster
  public readonly awsauth: AwsAuth

  constructor(scope: Construct, id: string, props: ekstackprops) {
    super(scope, id, props);

    // ============================================================================================================================================
    // Base Constructs
    // ============================================================================================================================================
    // Get current VPC-ID
    const vpc = this.getOrCreateVpc(this);

    // Create Security Group for EKS cluster
    const fpl_cluster_SecurityGroup = new SecurityGroup(this, 'fpl_cluster_SecurityGroup', {
      allowAllOutbound: true,
      securityGroupName: this.getOrCreateEksName(this) + '-SecurityGroup',
      vpc: vpc,
    });
    // Create Admin Role for cluster
    const eksAdminRole = new Role(this, 'FPL_EKS_Admin_Role', {
      roleName: this.getOrCreateEksName(this) + '-FPL_EKS_Admin_Role',
      assumedBy: new ServicePrincipal('eks.amazonaws.com'),
      managedPolicies: [
        // SSM Manager Permissions
        ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
        ManagedPolicy.fromAwsManagedPolicyName("AmazonEKSServicePolicy"),
        ManagedPolicy.fromAwsManagedPolicyName("AmazonEKSClusterPolicy"),
      ],
    });

    // Need KMS Key for EKS Envelope Encryption, if deleted, KMS will wait default (30 days) time before removal.
    const clusterKmsKey = new Key(this, 'ekskmskey', {
      enableKeyRotation: true,
      alias: cdk.Fn.join('', ['alias/', 'eks/', this.getOrCreateEksName(this)]),
    });
    // ============================================================================================================================================
    // Cluster Creation
    // ============================================================================================================================================

    // Create EKS Cluster and define all properties
    this.cluster = new Cluster(this, 'EKSCluster', {
      version: KubernetesVersion.V1_28,
      defaultCapacity: 0,
      // https://aws.github.io/aws-eks-best-practices/security/docs/iam/#make-the-eks-cluster-endpoint-private
      endpointAccess: EndpointAccess.PRIVATE,
      vpc: vpc,
      vpcSubnets: [{ subnetType: aws_ec2.SubnetType.PRIVATE_WITH_EGRESS }],
      kubectlLayer: new KubectlV28Layer(this, 'kubectl'),
      secretsEncryptionKey: clusterKmsKey,
      mastersRole: eksAdminRole,
      clusterName: this.getOrCreateEksName(this),
      coreDnsComputeType: CoreDnsComputeType.EC2,
      clusterLogging: [
          ClusterLoggingTypes.API,
          ClusterLoggingTypes.AUTHENTICATOR,
          ClusterLoggingTypes.SCHEDULER,
      ],
      placeClusterHandlerInVpc: true,
      clusterHandlerEnvironment:  { AWS_STS_REGIONAL_ENDPOINTS: 'regional'},
      kubectlEnvironment:         { AWS_STS_REGIONAL_ENDPOINTS: 'regional'}
    });

    // Allow BastionHost security group access to EKS Control Plane
    fpl_cluster_SecurityGroup.connections.allowTo(this.cluster, Port.tcp(443), 'Allow between BastionHost and EKS ');
    // Create AWS Authenticator object to add IAM principals to the EKS cluster
    this.awsauth = new AwsAuth(this, 'EKS_AWSAUTH', {
      cluster: this.cluster,
    });

    const yaml = require('js-yaml');
    // Read in the manifest for AWS auth Roles
    const manifestConsoleViewGroup = yaml.loadAll(fs.readFileSync('manifests/consoleViewOnlyGroup.yaml', 'utf-8')) as [Record<string, any>];
    const manifestConsoleViewGroupDeploy = new KubernetesManifest(this, 'eks-group-view-only', {
      cluster: this.cluster,
      manifest: manifestConsoleViewGroup,
    });
    this.awsauth.node.addDependency(manifestConsoleViewGroupDeploy);
    this.awsauth.addMastersRole(eksAdminRole, `${eksAdminRole.roleArn}/{{SessionName}}`);

    // Patch aws-node daemonset to use IRSA via EKS Addons, do before nodes are created
    // https://aws.github.io/aws-eks-best-practices/security/docs/iam/#update-the-aws-node-daemonset-to-use-irsa
    const awsNodeconditionsPolicy = new CfnJson(this, 'awsVpcCniconditionPolicy', {
      value: {
        [`${this.cluster.openIdConnectProvider.openIdConnectProviderIssuer}:aud`]: 'sts.amazonaws.com',
        [`${this.cluster.openIdConnectProvider.openIdConnectProviderIssuer}:sub`]: 'system:serviceaccount:kube-system:aws-node',
      },
    });

    const awsNodePrincipal = new OpenIdConnectPrincipal(this.cluster.openIdConnectProvider).withConditions({
      StringEquals: awsNodeconditionsPolicy,
    });

    const awsVpcCniRole = new Role(this, 'awsVpcCniRole', {
      assumedBy: awsNodePrincipal,
    });

    awsVpcCniRole.addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName('AmazonEKS_CNI_Policy'));
    (() => new CfnAddon(this, 'kube-proxy', {
      addonName: 'kube-proxy',
      resolveConflicts: 'OVERWRITE',
      serviceAccountRoleArn: awsVpcCniRole.roleArn,
      clusterName: this.cluster.clusterName,
      addonVersion: this.node.tryGetContext('eks-addon-kube-proxy-version'),
    }))();
    (() => new CfnAddon(this, 'vpc-cni', {
      addonName: 'vpc-cni',
      resolveConflicts: 'OVERWRITE',
      serviceAccountRoleArn: awsVpcCniRole.roleArn,
      clusterName: this.cluster.clusterName,
      addonVersion: this.node.tryGetContext('eks-addon-vpc-cni-version'),
    }))();

    (() => new CfnAddon(this, 'core-dns', {
      addonName: 'coredns',
      resolveConflicts: 'OVERWRITE',
      serviceAccountRoleArn: awsVpcCniRole.roleArn,
      clusterName: this.cluster.clusterName,
      addonVersion: this.node.tryGetContext('eks-addon-coredns-version'),
    }))();

    this.templateOptions.description = `(SO8020) - Sonatype Nexus Repository on AWS. Template version latest.`;
  }

  // ============================================================================================================================================
  // Helper Functions
  // ============================================================================================================================================

  // Create nodegroup IAM role in same stack as eks cluster to ensure there is not a circular dependency
  public createNodegroupRole(id: string): Role {
    const role = new Role(this, id, {
      assumedBy: new ServicePrincipal('ec2.amazonaws.com'),
    });

    // These roles are needed for the creation of nodes and containers for the creation of eks cluster.
    role.addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName('AmazonEKSWorkerNodePolicy'));
    role.addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName('AmazonEC2ContainerRegistryReadOnly'));
    this.awsauth.addRoleMapping(role, {
      username: 'system:node:{}}',
      groups: [
        'system:bootstrappers',
        'system:nodes',
      ],
    });
    return role;
  }
  // Use a given VPC or create one.
  private getOrCreateVpc(scope: Construct): IVpc {
    // use an existing vpc or create a new one using cdk context
    const stack = cdk.Stack.of(scope);

    if (stack.node.tryGetContext('use_vpc_id') !== undefined) {
      return Vpc.fromLookup(stack, 'EKSNetworking', { vpcId: stack.node.tryGetContext('use_vpc_id') });
    }
    const vpc = new Vpc(stack, stack.stackName + '-EKSNetworking', eksVpc);
    addEndpoint(stack, vpc);
    return vpc;
  }
  private getOrCreateEksName(scope: Construct): string {
    // use an existing eks or create a new one using cdk context
    const stack = cdk.Stack.of(scope);
    if (stack.node.tryGetContext('cluster_name') !== undefined) {
      return stack.node.tryGetContext('cluster_name');
    }
    return 'test_eks_cluster';
  }
}
