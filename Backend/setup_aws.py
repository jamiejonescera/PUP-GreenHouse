import boto3
import json
from botocore.exceptions import ClientError

def create_dynamodb_table():
    """Create DynamoDB table for Eco Pantry"""
    dynamodb = boto3.resource('dynamodb', region_name='ap-northeast-1')
    
    table_name = 'aws-fb-db-dynamo'  # Updated to match your project
    
    try:
        # Check if table exists
        table = dynamodb.Table(table_name)
        table.load()
        print(f"✅ Table {table_name} already exists")
        return True
    except ClientError:
        pass
    
    # Create table with composite key for Eco Pantry data structure
    try:
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[
                {
                    'AttributeName': 'user_id',
                    'KeyType': 'HASH'   # Partition key
                },
                {
                    'AttributeName': 'item_id', 
                    'KeyType': 'RANGE'  # Sort key
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'user_id',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'item_id',
                    'AttributeType': 'S'
                }
            ],
            BillingMode='PAY_PER_REQUEST'
        )
        
        print(f"⏳ Creating table {table_name}...")
        table.wait_until_exists()
        print(f"✅ Table {table_name} created successfully!")
        return True
        
    except ClientError as e:
        print(f"❌ Error creating table: {e}")
        return False

def create_s3_bucket():
    """Setup S3 bucket for Eco Pantry image storage"""
    s3 = boto3.client("s3", region_name="ap-northeast-1")
    bucket_name = "aws-fb-db-s3"  # Updated to match your project

    try:
        # Check if bucket exists
        s3.head_bucket(Bucket=bucket_name)
        print(f"✅ Using existing S3 bucket: {bucket_name}")
    except ClientError as e:
        if e.response['Error']['Code'] == '404':
            # Bucket doesn't exist, create it
            try:
                s3.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={
                        'LocationConstraint': 'ap-northeast-1'
                    }
                )
                print(f"✅ Created S3 bucket: {bucket_name}")
            except ClientError as create_error:
                print(f"❌ Error creating S3 bucket: {create_error}")
                return None
        else:
            print(f"❌ Error accessing S3 bucket: {e}")
            return None

    # Set up bucket policy for Eco Pantry
    try:
        bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowEcoPantryUserAccess",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::876497563387:user/team_flarebend"
                    },
                    "Action": [
                        "s3:PutObject",
                        "s3:GetObject",
                        "s3:DeleteObject",
                        "s3:ListBucket"
                    ],
                    "Resource": [
                        f"arn:aws:s3:::{bucket_name}",
                        f"arn:aws:s3:::{bucket_name}/*"
                    ]
                },
                {
                    "Sid": "PublicReadImages", 
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket_name}/images/*"
                }
            ]
        }

        s3.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(bucket_policy)
        )
        print(f"✅ Bucket policy updated for {bucket_name}")

    except ClientError as e:
        print(f"⚠️  Warning: Could not set bucket policy: {e}")
        print("   You may need to set this manually in AWS Console")

    return bucket_name

def setup_cors_for_bucket():
    """Setup CORS for S3 bucket to allow frontend access"""
    s3 = boto3.client("s3", region_name="ap-northeast-1")
    bucket_name = "aws-fb-db-s3"
    
    cors_config = {
        'CORSRules': [
            {
                'AllowedHeaders': ['*'],
                'AllowedMethods': ['GET', 'PUT', 'POST', 'DELETE'],
                'AllowedOrigins': ['http://localhost:3000', 'http://localhost:8000'],
                'ExposeHeaders': ['ETag'],
                'MaxAgeSeconds': 3000
            }
        ]
    }
    
    try:
        s3.put_bucket_cors(Bucket=bucket_name, CORSConfiguration=cors_config)
        print(f"✅ CORS configuration set for {bucket_name}")
    except ClientError as e:
        print(f"⚠️  Warning: Could not set CORS: {e}")

def seed_sample_data():
    """Add sample categories and locations for testing"""
    dynamodb = boto3.resource('dynamodb', region_name='ap-northeast-1')
    table = dynamodb.Table('aws-fb-db-dynamo')
    
    # Sample categories
    sample_categories = [
        "Plastic Bottles", "Glass Containers", "Paper Products", 
        "Electronics", "Textiles", "Metal Items", "Cardboard", "Other"
    ]
    
    # Sample PUP campus locations
    sample_locations = [
        {"location_id": "loc_1", "name": "Main Building Lobby", "description": "Near the information desk"},
        {"location_id": "loc_2", "name": "Library Entrance", "description": "Ground floor entrance"},
        {"location_id": "loc_3", "name": "Cafeteria Area", "description": "Near the main cafeteria"},
        {"location_id": "loc_4", "name": "Engineering Building", "description": "First floor lobby"},
        {"location_id": "loc_5", "name": "Student Center", "description": "Main hall"}
    ]
    
    try:
        # Add categories to table
        table.put_item(Item={
            'user_id': 'SYSTEM',
            'item_id': 'CATEGORIES',
            'data': sample_categories
        })
        
        # Add locations to table
        for location in sample_locations:
            table.put_item(Item={
                'user_id': 'SYSTEM',
                'item_id': f"LOCATION_{location['location_id']}",
                'data': location
            })
        
        print("✅ Sample data seeded successfully!")
        
    except ClientError as e:
        print(f"⚠️  Warning: Could not seed sample data: {e}")

def main():
    print("🌱 Setting up AWS resources for Eco Pantry...")
    
    # Create DynamoDB table
    if not create_dynamodb_table():
        return
    
    # Setup S3 bucket
    bucket_name = create_s3_bucket()
    if not bucket_name:
        return
    
    # Setup CORS for bucket
    setup_cors_for_bucket()
    
    # Seed sample data
    seed_sample_data()
    
    print(f"\n✅ Eco Pantry AWS setup complete!")
    print(f"📝 Your main.py should use:")
    print(f"   TABLE_NAME = 'aws-fb-db-dynamo'")
    print(f"   BUCKET_NAME = '{bucket_name}'")
    print(f"   Region: 'ap-northeast-1'")
    
    # Save configuration
    config = {
        'table_name': 'aws-fb-db-dynamo',
        'bucket_name': bucket_name,
        'region': 'ap-northeast-1'
    }
    
    with open('eco_pantry_config.json', 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"💾 Configuration saved to eco_pantry_config.json")
    print("\n🚀 Ready to run your Eco Pantry backend!")

if __name__ == "__main__":
    main()