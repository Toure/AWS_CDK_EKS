import { Stack } from 'aws-cdk-lib';
import {
    GatewayVpcEndpointAwsService,
    Vpc,
    FlowLogTrafficType,
    FlowLogDestination,
    InterfaceVpcEndpoint, IpAddresses,
} from 'aws-cdk-lib/aws-ec2';

export let addEndpoint: (stack: Stack, vpc: Vpc) => void;
addEndpoint = (stack: Stack, vpc: Vpc): void => {
    // Additional VPC Endpoint for EKS
    // https://docs.aws.amazon.com/eks/latest/userguide/private-clusters.html#vpc-endpoints-private-clusters
    (() => new InterfaceVpcEndpoint(stack, 'ecrapiVpcEndpoint', {
        open: true,
        vpc: vpc,
        service: {
            name: `com.amazonaws.${stack.region}.ecr.api`,
            port: 443,
        },
        privateDnsEnabled: true,
    }))();

    (() => new InterfaceVpcEndpoint(stack, 'ecradkrVpcEndpoint', {
        open: true,
        vpc: vpc,
        service: {
            name: `com.amazonaws.${stack.region}.ecr.dkr`,
            port: 443,
        },
        privateDnsEnabled: true,
    }))();
};

export const eksVpc = {
    ipAddress: IpAddresses.cidr('172.16.0.0/16'),
    maxAzs: 2,
    // S3/DynamoDB https://docs.aws.amazon.com/vpc/latest/privatelink/vpce-gateway.html
    gatewayEndpoints: {
        S3: {
            service: GatewayVpcEndpointAwsService.S3,
        },
    },
    flowLogs: {
        VpcFlowlogs: {
            destination: FlowLogDestination.toCloudWatchLogs(),
            trafficType: FlowLogTrafficType.ALL,
        },
    },
    // TWO Nat Gateways for higher availability
    natGateways: 2,
};

