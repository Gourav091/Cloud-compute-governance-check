resource "aws_dynamodb_table" "orc_results" {
    name = "orc-results"
    billing_mode = "PAY_PER_REQUEST"
    hash_key = "resource_id"   #partition key
    attribute {
        name = "resource_id"
        type= "S"       #String
    }

}