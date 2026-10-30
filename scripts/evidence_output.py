"""Reserve a fresh output directory; never reuse or traverse protected evidence."""
import os
from pathlib import Path


def reserve_output(output, protected_roots):
    target = Path(output).absolute()
    resolved = target.resolve()
    for root in protected_roots:
        root = Path(root).resolve()
        if resolved == root or resolved.is_relative_to(root) or root.is_relative_to(resolved):
            raise ValueError('PROTECTED_OUTPUT')
    for component in [target, *target.parents]:
        if os.path.lexists(component):
            info = component.lstat()
            if component.is_symlink() or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise ValueError('OUTPUT_REPARSE_POINT')
    target.mkdir(exist_ok=False)
    return target
