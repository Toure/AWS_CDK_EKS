import { Duration, RemovalPolicy, Stack, StackProps } from "aws-cdk-lib";
import {
    InstanceClass,
    InstanceSize,
    InstanceType,
    Peer,
    Port,
    SecurityGroup,
    SubnetType,
} from "aws-cdk-lib/aws-ec2";
import { Credentials, DatabaseInstance, DatabaseInstanceEngine, PostgresEngineVersion } from "aws-cdk-lib/aws-rds";
import {ISecretAttachmentTarget, Secret} from "aws-cdk-lib/aws-secretsmanager";
import { Construct } from "constructs";
import {Cluster} from "aws-cdk-lib/aws-eks";

interface RDSDataStackProps extends StackProps {
    eksCluster: Cluster,
}

export class RDSDataStack extends Stack {
    private dbInstance: ISecretAttachmentTarget;
    constructor(scope: Construct, id: string, props: RDSDataStackProps) {
        super(scope, id, props);

        const engine = DatabaseInstanceEngine.postgres({ version: PostgresEngineVersion.VER_13_7 });
        const instanceType = InstanceType.of(InstanceClass.T3, InstanceSize.MICRO);
        const port = 5432;
        const dbName = "nexus3";

        // create database master user secret and store it in Secrets Manager
        // TODO: We should store this information somewhere outside of the codebase
        const masterUserSecret = new Secret(this, "db-master-user-secret", {
            secretName: "db-master-user-secret",
            description: "Database master user credentials",
            generateSecretString: {
                secretStringTemplate: JSON.stringify({ username: "postgres" }),
                generateStringKey: "password",
                passwordLength: 16,
                excludePunctuation: true,
            },
        });

        const vpc = props.eksCluster.vpc;
        // Create a Security Group
        const dbSg = new SecurityGroup(this, "Database-SG", {
            securityGroupName: "Database-SG",
            vpc: vpc,
        });

        // Add Inbound rule
        dbSg.addIngressRule(
            Peer.ipv4(vpc.vpcCidrBlock),
            Port.tcp(port),
            `Allow port ${port} for database connection from only within the VPC (${vpc.vpcId})`
        );

        // create RDS instance (PostgreSQL)
        const dbInstance = new DatabaseInstance(this, "NextEra-Neux-DB-1", {
            vpc: vpc,
            vpcSubnets: { subnetType: SubnetType.PRIVATE_ISOLATED },
            instanceType,
            engine,
            port,
            securityGroups: [dbSg],
            databaseName: dbName,
            credentials: Credentials.fromSecret(masterUserSecret),
            backupRetention: Duration.days(0), // disable automatic DB snapshot retention
            deleteAutomatedBackups: true,
            removalPolicy: RemovalPolicy.DESTROY,
        });

        // DB connection settings will be appended to this secret (host, port, etc.)
        // masterUserSecret.attach(this.dbInstance);
    }
}