from langchain_core.pydantic_v1 import BaseModel, Field, validator
import validators
import traceback
import re

class HostNameInput(BaseModel):
    """
    For checking correctness of a DNS hostname. 

    :param hostname: DNS hostname
    :type hostname: str
    """
    hostname: str = Field(description="Must be a hostname such as www.google.com")
    @validator('hostname')
    def is_dns_address(cls, value) -> str:
        if not validators.domain(value):
            raise ValueError("Malformed hostname")
        return value


class DocumentFilename(BaseModel):
    """
    This class enforces typechecking for a provided file name. 

    :param file_name: name of a file, including extension. Remove any previous path before the filename.
    :type file_name: str
    """
    file_name: str = Field(description="Should be a filename string with a suffix, such as code.py or code.cpp - Nothing else is accepted. ")
    @validator('file_name')
    def validate_filename(cls, value):
        try:
            # Remove potential quotes before checking filename.
            file_name = value.replace("'", "").replace("\"", "")
            # This RegEx pattern should only accept filenames with a dot extension (e.g., code.cpp, app.py, a.txt)
            pattern = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9._-]*[a-zA-Z0-9])?\.[a-zA-Z0-9_-]+$", re.M)
            result = re.search(pattern, file_name)
        except Exception:
            traceback.print_exc()

        if not result:
            raise ValueError("Invalid filename.extension")
        return result.group()