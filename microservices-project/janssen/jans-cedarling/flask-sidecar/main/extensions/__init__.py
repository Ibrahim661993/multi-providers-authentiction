"""
Copyright (c) 2025, Gluu, Inc. 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from flask_smorest import Api, Blueprint
from flask_cors import CORS 
from main.base.cedarling.cedarling import CedarlingInstance

class BlueprintApi(Blueprint):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @staticmethod
    def _prepare_response_content(data):
        if data is not None:
            return data
        return None

api = Api()
cors = CORS(expose_headers="X-Pagination")
cedarling = CedarlingInstance()
