import boto3
import json

app = Flask(__name__)

# Initialize AWS Cognito client
cognito_client = boto3.client('cognito-idp')

USER_POOL_ID = 'your-user-pool-id'
CLIENT_ID = 'your-client-id'

# Initialize AWS clients
iam_client = boto3.client('iam')
rds_client = boto3.client('rds')
s3_client = boto3.client('s3')
sqs_client = boto3.client('sqs')

# Define AWS resources
RDS_DB_INSTANCE_CLASS = 'db.t2.micro'
S3_BUCKET_NAME = 'your-bucket-name'
IAM_ROLE_NAME = 'your-role-name'
SQS_QUEUE_NAME = 'your-queue-name'
SQS_QUEUE_URL = 'your-queue-url'

def create_rds_instance():
    # Create RDS instance
    response = rds_client.create_db_instance(
        DBName='your-db-name',
        DBInstanceIdentifier='your-db-instance-id',
        Engine='mysql',
        DBInstanceClass=RDS_DB_INSTANCE_CLASS,
        MasterUsername='your-db-username',
        MasterUserPassword='your-db-password',
        AllocatedStorage=20,
        MultiAZ=False,
        StorageType='gp2',
        PubliclyAccessible=True,
        Tags=[{'Key': 'Name', 'Value': 'YourDB'}]
    )
    db_instance_id = response['DBInstance']['DBInstanceIdentifier']
    print(f'RDS instance created with ID: {db_instance_id}')
    return db_instance_id

def create_s3_bucket():
    # Create S3 bucket
    s3_client.create_bucket(Bucket=S3_BUCKET_NAME)
    print(f'S3 bucket created with name: {S3_BUCKET_NAME}')

def create_iam_role():
    # Create IAM role
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }]
    }
    response = iam_client.create_role(
        RoleName=IAM_ROLE_NAME,
        AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    role_arn = response['Role']['Arn']
    print(f'IAM role created with ARN: {role_arn}')
    return role_arn

def create_sqs_queue():
    # Create SQS queue
    response = sqs_client.create_queue(QueueName=SQS_QUEUE_NAME)
    queue_url = response['QueueUrl']
    print(f'SQS queue created with URL: {queue_url}')
    return queue_url

@app.route('/register', methods=['POST'])
def register_user():
    username = request.json.get('username')
    password = request.json.get('password')
    email = request.json.get('email')

    try:
        response = cognito_client.admin_create_user(
            UserPoolId=USER_POOL_ID,
            Username=username,
            TemporaryPassword=password,
            UserAttributes=[
                {'Name': 'email', 'Value': email},
                {'Name': 'email_verified', 'Value': 'true'}
            ]
        )
        return jsonify({'message': 'User registered successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/login', methods=['POST'])
def login_user():
    username = request.json.get('username')
    password = request.json.get('password')

    try:
        response = cognito_client.initiate_auth(
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password,
                'SECRET_HASH': 'your-secret-hash'  # Optional if you're using secret hash
            },
            ClientId=CLIENT_ID
        )
        access_token = response['AuthenticationResult']['AccessToken']
        return jsonify({'access_token': access_token}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 401

@app.route('/update-profile', methods=['PUT'])
def update_profile():
    access_token = request.headers.get('Authorization').split(' ')[1]
    email = request.json.get('email')
    phone_number = request.json.get('phone_number')

    try:
        cognito_client.update_user_attributes(
            AccessToken=access_token,
            UserAttributes=[
                {'Name': 'email', 'Value': email},
                {'Name': 'phone_number', 'Value': phone_number}
            ]
        )
        return jsonify({'message': 'Profile updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/delete-user', methods=['DELETE'])
def delete_user():
    access_token = request.headers.get('Authorization').split(' ')[1]

    try:
        cognito_client.delete_user(
            AccessToken=access_token
        )
        return jsonify({'message': 'User deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/upload-file', methods=['POST'])
def upload_file():
    file = request.files['file']
    file_key = file.filename

    try:
        s3_client.upload_fileobj(file, S3_BUCKET_NAME, file_key)
        return jsonify({'message': 'File uploaded successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/download-file/<filename>', methods=['GET'])
def download_file(filename):
    try:
        s3_client.download_file(S3_BUCKET_NAME, filename, filename)
        # Here, you might return the file contents or stream it back to the client
        return jsonify({'message': 'File downloaded successfully'}), 200
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "404":
            return jsonify({'error': 'File not found'}), 404
        else:
            return jsonify({'error': str(e)}), 400

@app.route('/delete-file/<filename>', methods=['DELETE'])
def delete_file(filename):
    try:
        s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=filename)
        return jsonify({'message': 'File deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    
@app.route('/send-message', methods=['POST'])
def send_message():
    message_body = request.json.get('message_body')

    try:
        response = sqs_client.send_message(
            QueueUrl=SQS_QUEUE_URL,
            MessageBody=message_body
        )
        message_id = response['MessageId']
        return jsonify({'message': 'Message sent successfully', 'message_id': message_id}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/receive-message', methods=['GET'])
def receive_message():
    try:
        response = sqs_client.receive_message(
            QueueUrl=SQS_QUEUE_URL,
            MaxNumberOfMessages=1,
            VisibilityTimeout=30,  # Visibility timeout in seconds
            WaitTimeSeconds=0  # Wait time for messages in seconds
        )
        if 'Messages' in response:
            message = response['Messages'][0]
            message_body = message['Body']
            receipt_handle = message['ReceiptHandle']
            # Delete the message from the queue after processing
            sqs_client.delete_message(QueueUrl=SQS_QUEUE_URL, ReceiptHandle=receipt_handle)
            return jsonify({'message_body': message_body}), 200
        else:
            return jsonify({'message': 'No messages available'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Dummy data for orders (replace with database or actual data source)
orders = [
    {"id": 1, "customer_id": 1, "product_id": 101, "quantity": 2},
    {"id": 2, "customer_id": 2, "product_id": 102, "quantity": 1},
    {"id": 3, "customer_id": 1, "product_id": 103, "quantity": 3}
]

@app.route('/orders', methods=['GET'])
def get_orders():
    return jsonify(orders), 200

@app.route('/orders/<int:order_id>', methods=['GET'])
def get_order(order_id):
    order = next((order for order in orders if order['id'] == order_id), None)
    if order:
        return jsonify(order), 200
    else:
        return jsonify({'error': 'Order not found'}), 404

@app.route('/orders', methods=['POST'])
def create_order():
    data = request.json
    new_order = {
        'id': len(orders) + 1,
        'customer_id': data['customer_id'],
        'product_id': data['product_id'],
        'quantity': data['quantity']
    }
    orders.append(new_order)
    return jsonify(new_order), 201

@app.route('/orders/<int:order_id>', methods=['PUT'])
def update_order(order_id):
    data = request.json
    order = next((order for order in orders if order['id'] == order_id), None)
    if order:
        order.update(data)
        return jsonify(order), 200
    else:
        return jsonify({'error': 'Order not found'}), 404

@app.route('/orders/<int:order_id>', methods=['DELETE'])
def delete_order(order_id):
    global orders
    orders = [order for order in orders if order['id'] != order_id]
    return jsonify({'message': 'Order deleted successfully'}), 200

def main():
    # Create AWS resources
    rds_instance_id = create_rds_instance()
    create_s3_bucket()
    iam_role_arn = create_iam_role()
    sqs_queue_url = create_sqs_queue()

    # Additional operations such as user management, file storage, messaging, etc., can be added here

if __name__ == '__main__':
    main()
    app.run(debug=True)
