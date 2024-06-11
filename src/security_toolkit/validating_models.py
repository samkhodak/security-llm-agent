from langchain_core.pydantic_v1 import BaseModel, Field, validator
import validators
import traceback
import re
import os.path

class UrlInput(BaseModel):
    """
    For checking correctness of a provided URL.

    :param url: url
    :type url: str
    """
    url: str = Field(description="Must be a valid url or domain such as https://www.google.com or www.google.com")
    @validator('url')
    def is_url(cls, value) -> str:
        valid_url = validators.url(value)
        valid_domain = validators.domain(value)
        if valid_url == True or valid_domain == True:
            return value
        raise ValueError("Malformed URL. Given url is not a proper url or domain.")


class FilenameInput(BaseModel):
    """
    This class enforces the use of a filename within the current directory.

    :param file_name: Name of the file in the current directory.
    :type file_name: str
    """
    file_name: str = Field(description="Should be a filename string without a path - Nothing else is accepted. ")
    @validator('file_name')
    def validate_filename(cls, value) -> str:
        return value
        file_path = value
        # os.path will return nothing if path ends with '/' on unix systems.
        if (file_path[-1] == '/' or file_path[-1] == '\\'):
            file_path= file_path[:-1]
        
        final_filename = os.path.basename(file_path)

        if not final_filename:
            raise ValueError("Invalid filename. ")

        return final_filename

