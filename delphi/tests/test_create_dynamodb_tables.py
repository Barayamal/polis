from unittest.mock import MagicMock

import pytest

from create_dynamodb_tables import _create_tables, _verify_tables_active


def test_create_tables_raises_if_any_required_table_creation_fails():
    dynamodb = MagicMock()
    created_table = MagicMock()
    dynamodb.create_table.side_effect = [
        RuntimeError("forced create failure"),
        created_table,
    ]

    with pytest.raises(
        RuntimeError,
        match=r"Failed to create required DynamoDB tables: RequiredTable: forced create failure",
    ):
        _create_tables(
            dynamodb,
            {
                "RequiredTable": {
                    "KeySchema": [],
                    "AttributeDefinitions": [],
                },
                "LaterTable": {
                    "KeySchema": [],
                    "AttributeDefinitions": [],
                },
            },
            existing_tables=[],
        )

    assert dynamodb.create_table.call_count == 2
    created_table.meta.client.get_waiter.assert_called_once_with("table_exists")
    created_table.meta.client.get_waiter.return_value.wait.assert_called_once_with(
        TableName="LaterTable"
    )


def test_verify_tables_active_raises_for_missing_or_inactive_tables():
    dynamodb = MagicMock()

    def describe_table(*, TableName):
        if TableName == "MissingTable":
            raise RuntimeError("forced missing table")
        return {"Table": {"TableStatus": "CREATING"}}

    dynamodb.meta.client.describe_table.side_effect = describe_table

    with pytest.raises(RuntimeError, match=r"InactiveTable: status is CREATING"):
        _verify_tables_active(
            dynamodb,
            {"InactiveTable", "MissingTable"},
        )


def test_verify_tables_active_reads_back_every_required_table():
    dynamodb = MagicMock()
    dynamodb.meta.client.describe_table.return_value = {
        "Table": {"TableStatus": "ACTIVE"}
    }

    _verify_tables_active(dynamodb, {"FirstTable", "SecondTable"})

    assert {
        call.kwargs["TableName"]
        for call in dynamodb.meta.client.describe_table.call_args_list
    } == {"FirstTable", "SecondTable"}
