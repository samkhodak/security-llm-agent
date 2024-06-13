from pydantic import BaseModel, Field, field_validator, ValidationError
import validators
import os.path

class UrlInput(BaseModel):
    """
    For checking correctness of a provided URL.

    :param url: Url address.
    :type url: str
    """
    url: str = Field(description="Must be a valid url or domain such as https://www.google.com or www.google.com")
    @field_validator('url')
    @classmethod
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
    @field_validator('file_name')
    @classmethod
    def validate_filename(cls, value) -> str:
        if not value:
            raise ValueError("Please enter a filename.")

        # os.path.basename will return nothing if path ends with '/' on unix systems.
        if (value and (value[-1] == '/' or value[-1] == '\\')):
            value = value[:-1]

        final_filename = os.path.basename(value)
        final_filename = final_filename.strip()

        if not final_filename:
            raise ValueError("Invalid filename.")


        return final_filename

