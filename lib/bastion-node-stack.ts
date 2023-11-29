import * as cdk from 'aws-cdk-lib';
import {
    InstanceType,
    Port,
    BlockDeviceVolume,
    EbsDeviceVolumeType,
    Instance,
    MachineImage,
    SecurityGroup,
    Peer
} from 'aws-cdk-lib/aws-ec2';
import {
    PolicyStatement,
    Effect,
    Role,
    ManagedPolicy,
    ServicePrincipal,
} from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';
import {Cluster} from "aws-cdk-lib/aws-eks";

interface bastionprops extends cdk.StackProps {
    ekscluster: Cluster
}

export class BastionStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props: bastionprops) {
        super(scope, id, props);

        const vpc = props.ekscluster.vpc;
        // Locked Down Bastion Host Security Group to only allow outbound access to port 443.
        const bastionHostLinuxSecurityGroup = new SecurityGroup(this, 'bastionHostSecurityGroup', {
            allowAllOutbound: false,
            securityGroupName: props.ekscluster.clusterName + '-bastionSecurityGroup',
            vpc: vpc,
        });
        // Recommended to use connections to manage ingress/egress for security groups
        bastionHostLinuxSecurityGroup.connections.allowTo(Peer.anyIpv4(), Port.tcp(443), 'Outbound to 443 only');
        // Create Custom IAM Role and Policies for Bastion Host
        const bastionHostPolicy = new ManagedPolicy(this, 'bastionHostManagedPolicy');
        bastionHostPolicy.addStatements(new PolicyStatement({
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
        const bastionHostRole = new Role(this, 'bastionHostRole', {
            roleName: props.ekscluster.clusterName + '-bastion-host',
            assumedBy: new ServicePrincipal('ec2.amazonaws.com'),
            managedPolicies: [
                // SSM Manager Permissions
                ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
                // Read only EKS Permissions
                bastionHostPolicy,
            ],
        });

        // Create Bastion Host, connect using Session Manager
        new Instance(this, 'BastionEKSHost', {
            // Defaults to private subnets
            // https://docs.aws.amazon.com/cdk/api/latest/docs/@aws-cdk_aws-ec2.Instance.html#vpcsubnets
            vpc: vpc,
            instanceName: props.ekscluster.clusterName + '-EKSBastionHost',
            instanceType: new InstanceType('t3.small'),
            // Always use Latest Amazon Linux 2 instance, if new AMI is released will replace instance to keep it patched
            // If replaced with specific AMI, ensure SSM Agent is installed and running
            machineImage: MachineImage.latestAmazonLinux2023(),
            securityGroup: bastionHostLinuxSecurityGroup,
            role: bastionHostRole,
            // Ensure Bastion host EBS volume is encrypted
            blockDevices: [{
                deviceName: '/dev/xvda',
                volume: BlockDeviceVolume.ebs(30, {
                    volumeType: EbsDeviceVolumeType.GP3,
                    encrypted: true,
                }),
            }],
        });

    }
}