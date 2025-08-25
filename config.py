import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    FILEPATH_THE_HARVESTER = os.getenv("FILEPATH_THE_HARVESTER", "")
    OUTPUT_PATH_THE_HARVESTER = os.getenv("OUTPUT_PATH_THE_HARVESTER", "")
    SECRET_KEY = os.getenv("SECRET_KEY")
