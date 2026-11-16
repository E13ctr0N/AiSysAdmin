import pytest

from agensysadmin.validation import (
    shell_quote,
    validate_absolute_path,
    validate_backup_name,
    validate_container_name,
    validate_package_name,
    validate_service_name,
    validate_user_name,
)


@pytest.mark.parametrize(
    ("validator", "value"),
    [
        (validate_package_name, "curl;id"),
        (validate_service_name, "nginx --now"),
        (validate_container_name, "web$(id)"),
        (validate_user_name, "root;id"),
        (validate_backup_name, "../../backup"),
    ],
)
def test_identifier_validators_reject_shell_syntax(validator, value):
    with pytest.raises(ValueError):
        validator(value)


@pytest.mark.parametrize("value", ["relative", "/ok\nnot-ok", "/ok\x00not-ok"])
def test_absolute_path_rejects_relative_and_control_characters(value):
    with pytest.raises(ValueError):
        validate_absolute_path(value)


def test_shell_quote_preserves_newline_content_without_evaluating_it():
    assert shell_quote("first\n$(id) 'quoted'") == "'first\n$(id) '\"'\"'quoted'\"'\"''"
