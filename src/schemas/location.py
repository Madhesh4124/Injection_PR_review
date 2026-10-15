"""Location schema for findings and injections."""

from pathlib import PurePosixPath, PureWindowsPath
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.schemas.taxonomies import SourceKind


class Location(BaseModel):
    """Location reference within a pull request or repository."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    source_kind: SourceKind
    path: Optional[str] = Field(
        default=None,
        description="Repository-relative file path, or null for pr_description.",
    )
    start_line: int = Field(ge=1, description="One-based starting line number.")
    end_line: int = Field(ge=1, description="One-based ending line number (end_line >= start_line).")

    @model_validator(mode="after")
    def validate_location_integrity(self) -> "Location":
        """Enforce line order and path containment semantics."""
        if self.end_line < self.start_line:
            raise ValueError(
                f"end_line ({self.end_line}) cannot be less than start_line ({self.start_line})"
            )

        if self.source_kind == SourceKind.PR_DESCRIPTION:
            if self.path is not None:
                raise ValueError("path must be null/None when source_kind is 'pr_description'")
        else:
            if not self.path or not self.path.strip():
                raise ValueError(
                    f"path is required and cannot be empty when source_kind is '{self.source_kind.value}'"
                )

            # Security: Path must be strictly relative and free of directory traversal
            p_posix = PurePosixPath(self.path)
            p_win = PureWindowsPath(self.path)
            if p_posix.is_absolute() or p_win.is_absolute() or self.path.startswith("/") or self.path.startswith("\\"):
                raise ValueError(f"path must be repository-relative, got absolute path: {self.path}")

            parts = p_posix.parts
            if ".." in parts:
                raise ValueError(f"path traversal (..) is strictly prohibited: {self.path}")

        return self
