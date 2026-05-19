"""
Pydantic schemas để validate JSON responses từ LLM API
"""
from pydantic import BaseModel, Field, validator
from typing import Dict, List, Optional, Any


class SemanticClassificationResponse(BaseModel):
    """Validate response từ classify_unknown_fields()"""
    
    # Cho phép thêm fields không được định nghĩa sẵn
    class Config:
        extra = "allow"  # Cho phép field động từ LLM
    
    # Các giá trị hợp lệ
    @validator("*", pre=True)
    def validate_category(cls, v):
        """Mỗi field phải có value là category string"""
        valid_categories = {"identity", "auth/workflow", "finance", "unknown"}
        if not isinstance(v, str):
            raise ValueError(f"Category must be string, got {type(v).__name__}")
        if v not in valid_categories:
            raise ValueError(f"Invalid category '{v}'. Must be one of {valid_categories}")
        return v


class IdentityClusterResponse(BaseModel):
    """Validate response từ cluster_identities()"""
    clusters: List[List[str]] = Field(
        ..., 
        description="List of clusters, each cluster is a list of field names"
    )
    
    @validator("clusters")
    def validate_clusters(cls, v):
        """Validate clusters structure"""
        if not isinstance(v, list):
            raise ValueError("clusters must be a list")
        for cluster in v:
            if not isinstance(cluster, list):
                raise ValueError("Each cluster must be a list")
            if not cluster:  # Empty cluster
                raise ValueError("Clusters cannot be empty")
            for field in cluster:
                if not isinstance(field, str):
                    raise ValueError(f"Field name must be string, got {type(field).__name__}")
        return v


class PayloadFieldValue(BaseModel):
    """Validate individual field value trong payload"""
    # Cho phép bất kỳ giá trị nào (string, int, bool, dict, list)
    value: Optional[Any] = None
    
    class Config:
        arbitrary_types_allowed = True


class PayloadResponse(BaseModel):
    """Validate response từ generate_payload()"""
    # Cho phép dynamic fields (tên field tùy API)
    class Config:
        extra = "allow"
        arbitrary_types_allowed = True
    
    @validator("*", pre=True)
    def validate_field_value(cls, v):
        """Mỗi field value phải là primitive type hoặc dict/list"""
        if v is None:
            return v
        if isinstance(v, (str, int, float, bool)):
            return v
        if isinstance(v, dict):
            # Nested object
            return v
        if isinstance(v, list):
            # Array (mỗi item phải là primitive hoặc dict)
            return v
        raise ValueError(f"Field value must be primitive/dict/list, got {type(v).__name__}")


class APIErrorResponse(BaseModel):
    """Validate error response từ API"""
    error: str = Field(..., description="Error message")
    status_code: Optional[int] = None
    details: Optional[Dict[str, Any]] = None


class LLMRepairResponse(BaseModel):
    """Validate response từ repair_payload()"""
    # Tương tự PayloadResponse nhưng cho repair
    class Config:
        extra = "allow"
        arbitrary_types_allowed = True


# Helper function để validate JSON response từ LLM
def validate_json_response(raw_json: str, schema_class: type) -> Any:
    """
    Validate raw JSON string từ LLM response
    
    Args:
        raw_json: JSON string từ LLM
        schema_class: Pydantic model để validate
    
    Returns:
        Validated data nếu pass, raise ValueError nếu fail
    
    Raises:
        ValueError: Nếu JSON không valid hoặc không match schema
    """
    import json
    from pydantic import ValidationError
    
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON from LLM: {e}")
    
    try:
        validated = schema_class(**data)
        return validated.dict()
    except ValidationError as e:
        raise ValueError(f"LLM response doesn't match expected schema: {e}")
