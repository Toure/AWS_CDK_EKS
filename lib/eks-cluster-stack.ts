import * as cdk from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import {CfnJson} from 'aws-cdk-lib';
import {
  FlowLogDestination,
  GatewayVpcEndpointAwsService,
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
import {KubectlV27Layer} from '@aws-cdk/lambda-layer-kubectl-v27';
import {Construct} from 'constructs';
import * as fs from "fs";
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
    const vpc = this.getVpc(this);

    // Create Security Group for EKS cluster
    // Locked Down cluster Security Group to only allow outbound access to port 443. TODO: harden the access
    const fpl_cluster_SecurityGroup = new SecurityGroup(this, 'fpl_cluster_SecurityGroup', {
      allowAllOutbound: true,
      securityGroupName: this.getOrCreateEksName(this) + '-SecurityGroup',
      vpc: vpc,
    });
    // TODO: harden access
    // Recommended to use connections to manage ingress/egress for security groups
    // fpl_cluster_SecurityGroup.connections.allowTo(Peer.anyIpv4(), Port.tcp(443), 'Outbound to 443 only');
    // TODO: Remove this as this SG is to wide open
    // fpl_cluster_SecurityGroup.connections.allowFromAnyIpv4(Port.allTcp());

    // Create Admin IAM Role and Policies for EKS cluster
    // https://docs.aws.amazon.com/eks/latest/userguide/security_iam_id-based-policy-examples.html#policy_example3
    const eksAdminPolicy = new ManagedPolicy(this, 'FPL_EKS_Admin_Policy');
    eksAdminPolicy.addStatements(new PolicyStatement({
      resources: ['*'],
      actions: [
        'eks:DescribeNodegroup',
        'eks:ListNodegroups',
        'eks:DescribeCluster',
        'eks:ListClusters',
        'eks:AccessKubernetesApi',
        'eks:ListUpdates',
        'eks:ListFargateProfiles',
      ],
      effect: Effect.ALLOW,
      sid: 'EKSReadonly',
    }));

    // Create Admin Role for cluster
    const eksAdminRole = new Role(this, 'FPL_EKS_Admin_Role', {
      roleName: this.getOrCreateEksName(this) + '-FPL_EKS_Admin_Role',
      assumedBy: new ServicePrincipal('eks.amazonaws.com'),
      managedPolicies: [
        // SSM Manager Permissions
        ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
        eksAdminPolicy,
      ],
    });

    // Need KMS Key for EKS Envelope Encryption, if deleted, KMS will wait default (30 days) time before removal.
    const clusterKmsKey = new Key(this, 'ekskmskey', {
      enableKeyRotation: true,
      alias: cdk.Fn.join('', ['alias/', 'eks/', this.getOrCreateEksName(this)]),
    });

    // ============================================================================================================================================
    // S3 Constructs
    // ============================================================================================================================================
    const logBucket = new s3.Bucket(this, 'LogBucket', {
      encryption: s3.BucketEncryption.S3_MANAGED,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      serverAccessLogsPrefix: 'logBucketAccessLog',
    });

    if (!logBucket) {
      throw new Error('S3 logBucket failed to create.');
    }

    const nexusBlobBucket = new s3.Bucket(this, 'nexus3-blobstore', {
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      encryption: s3.BucketEncryption.S3_MANAGED,
      serverAccessLogsBucket: logBucket,
      serverAccessLogsPrefix: 'blobstoreBucketAccessLog',
      enforceSSL: true,
    });

    if (!nexusBlobBucket) {
      throw new Error('S3 nexusBlobBucket failed to create.');
    }

    const flowLogPrefix = 'vpcFlowLogs';
    vpc.addFlowLog('VpcFlowlogs', {
      destination: FlowLogDestination.toS3(logBucket, flowLogPrefix),
    });

    logBucket.addToResourcePolicy(new PolicyStatement({
      sid: 'AWSLogDeliveryWrite',
      principals: [new ServicePrincipal('delivery.logs.amazonaws.com')],
      actions: ['s3:PutObject'],
      resources: [logBucket.arnForObjects(`${flowLogPrefix}/AWSLogs/${cdk.Aws.ACCOUNT_ID}/*`)],
      conditions: {
        StringEquals: {
          's3:x-amz-acl': 'bucket-owner-full-control',
        },
      },
    }));

    logBucket.addToResourcePolicy(new PolicyStatement({
      sid: 'AWSLogDeliveryCheck',
      principals: [new ServicePrincipal('delivery.logs.amazonaws.com')],
      actions: [
        's3:GetBucketAcl',
        's3:ListBucket',
      ],
      resources: [logBucket.bucketArn],
    }));

    // ============================================================================================================================================
    // Nexus S3 bucket blobstore constructs
    // ============================================================================================================================================


    // add an enpoint control to the gateway: EC2 nodes and S3 bucket
    // Controlling access from VPC endpoints with bucket policies:
    // https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies-vpc-endpoint.html#example-bucket-policies-restrict-accesss-vpc-endpoint
    if (vpc instanceof Vpc) {
      const gatewayEndpoint = vpc.addGatewayEndpoint('s3', {
        service: GatewayVpcEndpointAwsService.S3,
      });
      nexusBlobBucket.addToResourcePolicy(new PolicyStatement({
        effect: Effect.DENY,
        actions: ['s3:*'],
        principals: [new AccountPrincipal(cdk.Aws.ACCOUNT_ID)],
        resources: [
          nexusBlobBucket.bucketArn,
          nexusBlobBucket.arnForObjects('*'),
        ],
        conditions: {
          StringNotEquals: {
            'aws:SourceVpce': gatewayEndpoint.vpcEndpointId,
          },
        },
      }));
    }

    // ============================================================================================================================================
    // Cluster Creation
    // ============================================================================================================================================

    // Create EKS Cluster and define all properties
    this.cluster = new Cluster(this, 'EKSCluster', {
      version: KubernetesVersion.V1_27,
      defaultCapacity: 0,
      // https://aws.github.io/aws-eks-best-practices/security/docs/iam/#make-the-eks-cluster-endpoint-private
      endpointAccess: EndpointAccess.PRIVATE,
      vpc: vpc,
      kubectlLayer: new KubectlV27Layer(this, 'kubectl'),
      secretsEncryptionKey: clusterKmsKey,
      mastersRole: eksAdminRole,
      clusterName: this.getOrCreateEksName(this),
      coreDnsComputeType: CoreDnsComputeType.EC2,
      clusterLogging: [
          ClusterLoggingTypes.API,
          ClusterLoggingTypes.AUTHENTICATOR,
          ClusterLoggingTypes.SCHEDULER,
      ]

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
    role.addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName('AmazonEKSWorkerNodePolicy'));
    role.addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName('AmazonEC2ContainerRegistryReadOnly'));
    this.awsauth.addRoleMapping(role, {
      username: 'system:node:{{EC2PrivateDNSName}}',
      groups: [
        'system:bootstrappers',
        'system:nodes',
      ],
    });
    return role;
  }

  private getVpc(scope: Construct) {
    // retrieve vpc id from the cli keyname: use_vpc_id=xxxxxxx
    const stack = cdk.Stack.of(scope);
    return Vpc.fromLookup(stack, 'EKSNetworking', { vpcId: stack.node.tryGetContext('use_vpc_id') });
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
