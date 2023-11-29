import * as cdk from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import {
    FlowLogDestination,
    GatewayVpcEndpointAwsService,
    Vpc
} from 'aws-cdk-lib/aws-ec2';
import {
    Cluster,
} from 'aws-cdk-lib/aws-eks';
import {
    AccountPrincipal,
    Effect,
    PolicyStatement,
    ServicePrincipal
} from 'aws-cdk-lib/aws-iam';

import {Construct} from 'constructs';
interface s3props extends cdk.StackProps {
    ekscluster: Cluster
}

export class S3Stack extends cdk.Stack {
    constructor(scope: Construct, id: string, props: s3props) {
        super(scope, id, props);

        // ============================================================================================================================================
        // S3 Constructs
        // ============================================================================================================================================
        const vpc = props.ekscluster.vpc;
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
    }
}