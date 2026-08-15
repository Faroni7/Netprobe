"""
NetSec Platform - Search Engine

Query language and search functionality for network security data.
Supports filtering flows, findings, artifacts, and events.
"""

import re
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum


class Operator(Enum):
    """Comparison operators for search queries."""
    EQ = "=="
    NE = "!="
    GT = ">"
    LT = "<"
    GTE = ">="
    LTE = "<="
    CONTAINS = "contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    MATCHES = "matches"  # Regex
    IN = "in"


@dataclass
class QueryCondition:
    """Represents a single query condition."""
    field: str
    operator: Operator
    value: Any


@dataclass
class ParsedQuery:
    """Represents a parsed search query."""
    conditions: List[QueryCondition]
    logical_op: str = "AND"  # AND or OR
    errors: List[str] = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []


class SearchEngine:
    """
    Search engine for NetSec Platform.
    
    Supports a simple query language:
    - src.ip == "10.0.0.25"
    - dst.port == 443
    - dns.name contains "example.com"
    - tls.sni == "example.com"
    - proto == "HTTP"
    - encryption == "PLAINTEXT"
    - sens_data.detected == true
    - sens_data.type == "SESSION_COOKIE"
    - finding.severity >= "HIGH"
    
    Compound expressions with AND/OR:
    - src.ip == "10.0.0.25" AND dst.port == 80
    - encryption == "PLAINTEXT" OR finding.severity == "CRITICAL"
    """
    
    # Field mappings to database columns
    FIELD_MAPPINGS = {
        # Flow fields
        "src.ip": "src_ip",
        "src.port": "src_port",
        "dst.ip": "dst_ip",
        "dst.port": "dst_port",
        "proto": "protocol",
        "app.proto": "app_protocol",
        "encryption": "encryption",
        "security": "security_quality",
        "start_time": "start_time",
        "end_time": "end_time",
        "duration": "duration_ms",
        "packets.sent": "packets_sent",
        "packets.received": "packets_received",
        "bytes.sent": "bytes_sent",
        "bytes.received": "bytes_received",
        
        # DNS fields
        "dns.name": "query_name",
        "dns.type": "query_type",
        "dns.response_code": "response_code",
        
        # TLS fields
        "tls.sni": "sni",
        "tls.version": "tls_version",
        "tls.cipher": "cipher_suite",
        
        # HTTP fields
        "http.method": "method",
        "http.host": "host",
        "http.uri": "uri",
        "http.status": "status_code",
        
        # Finding fields
        "finding.severity": "severity",
        "finding.confidence": "confidence",
        "finding.status": "status",
        "finding.title": "title",
        
        # Asset fields
        "asset.ip": "ip_address",
        "asset.mac": "mac_address",
        "asset.hostname": "hostname",
        
        # Sensitive data fields
        "sens_data.type": "artifact_type",
        "sens_data.detected": "detected",
    }
    
    # Severity ordering for comparisons
    SEVERITY_ORDER = {
        "INFO": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }
    
    def __init__(self):
        pass
    
    def parse_query(self, query_string: str) -> ParsedQuery:
        """
        Parse a query string into structured conditions.
        
        Example queries:
        - 'src.ip == "10.0.0.25"'
        - 'dst.port == 443 AND proto == "TCP"'
        - 'dns.name contains "example.com"'
        """
        conditions = []
        errors = []
        logical_op = "AND"
        
        if not query_string or not query_string.strip():
            return ParsedQuery(conditions=[], errors=errors)
        
        # Split by AND/OR (case-insensitive)
        tokens = re.split(r'\s+(AND|OR)\s+', query_string, flags=re.IGNORECASE)
        
        # Check for consistent logical operator
        operators = [t for t in tokens if t.upper() in ("AND", "OR")]
        if operators:
            if all(op.upper() == "AND" for op in operators):
                logical_op = "AND"
            elif all(op.upper() == "OR" for op in operators):
                logical_op = "OR"
            else:
                errors.append("Cannot mix AND and OR operators. Use parentheses for complex queries.")
        
        # Process each condition
        for token in tokens:
            token = token.strip()
            if token.upper() in ("AND", "OR"):
                continue
            
            condition = self._parse_condition(token)
            if condition:
                conditions.append(condition)
            else:
                errors.append(f"Failed to parse condition: {token}")
        
        return ParsedQuery(
            conditions=conditions,
            logical_op=logical_op,
            errors=errors
        )
    
    def _parse_condition(self, condition_str: str) -> Optional[QueryCondition]:
        """Parse a single condition from string."""
        
        # Try different operators in order of specificity
        operator_patterns = [
            (r'(\S+)\s*==\s*(.+)', Operator.EQ),
            (r'(\S+)\s*!=\s*(.+)', Operator.NE),
            (r'(\S+)\s*>=\s*(.+)', Operator.GTE),
            (r'(\S+)\s*<=\s*(.+)', Operator.LTE),
            (r'(\S+)\s*>\s*(.+)', Operator.GT),
            (r'(\S+)\s*<\s*(.+)', Operator.LT),
            (r'(\S+)\s+contains\s+(.+)', Operator.CONTAINS),
            (r'(\S+)\s+starts_with\s+(.+)', Operator.STARTS_WITH),
            (r'(\S+)\s+ends_with\s+(.+)', Operator.ENDS_WITH),
            (r'(\S+)\s+matches\s+(.+)', Operator.MATCHES),
            (r'(\S+)\s+in\s+(.+)', Operator.IN),
        ]
        
        for pattern, op in operator_patterns:
            match = re.match(pattern, condition_str, re.IGNORECASE)
            if match:
                field = match.group(1).strip()
                value_str = match.group(2).strip()
                
                # Parse value
                value = self._parse_value(value_str, op)
                
                # Validate field
                db_field = self.FIELD_MAPPINGS.get(field)
                if not db_field:
                    # Allow unknown fields but log warning
                    db_field = field.lower().replace('.', '_')
                
                return QueryCondition(field=db_field, operator=op, value=value)
        
        return None
    
    def _parse_value(self, value_str: str, operator: Operator) -> Any:
        """Parse a value string into appropriate type."""
        
        # Remove quotes
        if (value_str.startswith('"') and value_str.endswith('"')) or \
           (value_str.startswith("'") and value_str.endswith("'")):
            return value_str[1:-1]
        
        # Boolean
        if value_str.lower() == 'true':
            return True
        if value_str.lower() == 'false':
            return False
        
        # Integer
        try:
            return int(value_str)
        except ValueError:
            pass
        
        # Float
        try:
            return float(value_str)
        except ValueError:
            pass
        
        # For IN operator, parse as list
        if operator == Operator.IN:
            if value_str.startswith('[') and value_str.endswith(']'):
                items = value_str[1:-1].split(',')
                return [self._parse_value(item.strip(), Operator.EQ) for item in items]
        
        # Default to string
        return value_str
    
    def build_sql_filter(self, parsed_query: ParsedQuery) -> Tuple[str, List[Any]]:
        """
        Build SQL WHERE clause from parsed query.
        
        Returns:
            Tuple of (where_clause, parameters)
        """
        if not parsed_query.conditions:
            return ("1=1", [])
        
        clauses = []
        params = []
        
        for condition in parsed_query.conditions:
            clause, param = self._condition_to_sql(condition)
            if clause:
                clauses.append(clause)
                if param is not None:
                    params.append(param)
        
        logical_operator = parsed_query.logical_op
        where_clause = f" {logical_operator} ".join(clauses)
        
        return (where_clause, params)
    
    def _condition_to_sql(self, condition: QueryCondition) -> Tuple[Optional[str], Any]:
        """Convert a QueryCondition to SQL clause."""
        
        field = condition.field
        op = condition.operator
        value = condition.value
        
        # Handle severity comparison specially
        if field == 'severity' and op in (Operator.GT, Operator.GTE, Operator.LT, Operator.LTE):
            return self._severity_comparison(field, op, value)
        
        # Standard operators
        if op == Operator.EQ:
            return (f"{field} = ?", value)
        elif op == Operator.NE:
            return (f"{field} != ?", value)
        elif op == Operator.GT:
            return (f"{field} > ?", value)
        elif op == Operator.LT:
            return (f"{field} < ?", value)
        elif op == Operator.GTE:
            return (f"{field} >= ?", value)
        elif op == Operator.LTE:
            return (f"{field} <= ?", value)
        elif op == Operator.CONTAINS:
            return (f"{field} LIKE ?", f"%{value}%")
        elif op == Operator.STARTS_WITH:
            return (f"{field} LIKE ?", f"{value}%")
        elif op == Operator.ENDS_WITH:
            return (f"{field} LIKE ?", f"%{value}")
        elif op == Operator.MATCHES:
            # SQLite REGEXP requires custom implementation
            # For now, use LIKE with wildcards
            return (f"{field} LIKE ?", f"%{value}%")
        elif op == Operator.IN:
            if isinstance(value, list):
                placeholders = ", ".join(["?" for _ in value])
                return (f"{field} IN ({placeholders})", value)
            return (None, None)
        
        return (None, None)
    
    def _severity_comparison(self, field: str, op: Operator, value: str) -> Tuple[str, Any]:
        """Handle severity level comparisons."""
        
        if not isinstance(value, str):
            return (None, None)
        
        value_upper = value.upper()
        if value_upper not in self.SEVERITY_ORDER:
            return (None, None)
        
        threshold = self.SEVERITY_ORDER[value_upper]
        
        if op == Operator.GT:
            return (f"(CASE {field} " + 
                    "WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 " +
                    "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 WHEN 'INFO' THEN 0 END) > ?",
                    threshold)
        elif op == Operator.GTE:
            return (f"(CASE {field} " +
                    "WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 " +
                    "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 WHEN 'INFO' THEN 0 END) >= ?",
                    threshold)
        elif op == Operator.LT:
            return (f"(CASE {field} " +
                    "WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 " +
                    "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 WHEN 'INFO' THEN 0 END) < ?",
                    threshold)
        elif op == Operator.LTE:
            return (f"(CASE {field} " +
                    "WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 " +
                    "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 WHEN 'INFO' THEN 0 END) <= ?",
                    threshold)
        
        return (None, None)
    
    def matches(self, record: Dict[str, Any], parsed_query: ParsedQuery) -> bool:
        """
        Check if a record matches the parsed query (for in-memory filtering).
        
        Args:
            record: Dictionary representing a database row
            parsed_query: Parsed query to evaluate
        
        Returns:
            True if record matches all conditions (AND) or any condition (OR)
        """
        if not parsed_query.conditions:
            return True
        
        results = []
        for condition in parsed_query.conditions:
            result = self._evaluate_condition(record, condition)
            results.append(result)
        
        if parsed_query.logical_op == "AND":
            return all(results)
        else:  # OR
            return any(results)
    
    def _evaluate_condition(self, record: Dict[str, Any], condition: QueryCondition) -> bool:
        """Evaluate a single condition against a record."""
        
        field = condition.field
        op = condition.operator
        value = condition.value
        
        # Get field value from record
        record_value = record.get(field)
        if record_value is None:
            return False
        
        # Type conversion
        if isinstance(value, str) and isinstance(record_value, (int, float)):
            try:
                value = type(record_value)(value)
            except (ValueError, TypeError):
                pass
        
        # Evaluate based on operator
        if op == Operator.EQ:
            return record_value == value
        elif op == Operator.NE:
            return record_value != value
        elif op == Operator.GT:
            return record_value > value
        elif op == Operator.LT:
            return record_value < value
        elif op == Operator.GTE:
            return record_value >= value
        elif op == Operator.LTE:
            return record_value <= value
        elif op == Operator.CONTAINS:
            return str(value).lower() in str(record_value).lower()
        elif op == Operator.STARTS_WITH:
            return str(record_value).lower().startswith(str(value).lower())
        elif op == Operator.ENDS_WITH:
            return str(record_value).lower().endswith(str(value).lower())
        elif op == Operator.MATCHES:
            try:
                return bool(re.search(str(value), str(record_value), re.IGNORECASE))
            except re.error:
                return False
        elif op == Operator.IN:
            if isinstance(value, list):
                return record_value in value
            return False
        
        return False
    
    def get_suggestions(self, prefix: str) -> List[str]:
        """Get field name suggestions for autocomplete."""
        prefix_lower = prefix.lower()
        return [
            field for field in self.FIELD_MAPPINGS.keys()
            if field.startswith(prefix_lower)
        ]


# Convenience function for quick queries
def search(query_string: str, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Quick search function for filtering records.
    
    Args:
        query_string: Query in search language
        records: List of dictionaries to filter
    
    Returns:
        Filtered list of matching records
    """
    engine = SearchEngine()
    parsed = engine.parse_query(query_string)
    
    if parsed.errors:
        raise ValueError(f"Query errors: {', '.join(parsed.errors)}")
    
    return [r for r in records if engine.matches(r, parsed)]
