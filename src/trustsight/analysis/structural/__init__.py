"""structural.py facade."""

import re
from ...differ import (
    _post_diff_lines,
    checksum_array_parity_in_text,
    is_skip_justified,
    map_diff_lines,
    source_array_has_command_substitution,
)
from ..base import _url_domain
from ..version import any_version_scalar_moved
from ..crossfire import _crossfire_findings
from ..sabotage import _sabotage_findings
from ..build import (
    _build_findings,
    _build_flag_findings,
    _function_shadow_findings,
    _INTERPRETER_FETCH,
    _reconstruction_findings,
)
from ...config import NETWORK_CLIENT
from ..delivery import (
    _delivery_findings,
    install_hook_transition,
    pinning_lost,
    source_name_host_swaps,
)
from ..dependencies import _dependency_findings
from ..ioc import _ioc_findings
from ..network import (
    _dlagents_override_findings,
    _moved_git_ref_findings,
)
from ..persistence import (
    _HOME_PREFIX_RE,
    _persistence_findings,
    _raw_targets,
    _WW_DIR_RE,
)
from ..version import _epoch_findings
from ...findings import stamp
from ...line_lex import strip_comment
from ...recipedoc import parse_recipe, recipe_states
from ...rules import find_line_in_diff
from ...diffdoc import parse_diff_lines
from ...tokenizer import split_lines
from ._checksums import (
    _CHECKSUM_ADDED_RE,
    _CHECKSUM_ARRAY_NAMES,
    _CHECKSUM_EMPTIED_RE,
    _CHECKSUM_REMOVED_LINE_RE,
    _CHECKSUM_SKIP_RE,
    _CHECKSUM_STRENGTH,
    _FETCH_IN_PACKAGE_RE,
    _HARDENING_OPTIONS,
    _INTERPRETER_FETCH_RE,
    _SCHEME_MARKERS,
    _family_values,
    _first_insertion_index,
    _ip_literal_hosts,
    _is_checksum_array,
    _is_subsequence,
    _line_has_scheme,
    _package_fetch_client,
    _removed_declarations,
    _require_content_change,
    _skip_positions,
    _url_host,
    _userinfo_urls,
    addendum4_findings,
    array_order_changes,
    isolated_checksum_insertion,
    recipe_checksum_parity_finding,
)
from ._common import (
    _BINARY_ARTIFACT_RE,
    _TRUSTED_BUCKETS,
)
from ._engine import (
    _structural_findings,
)
from ._hooks import (
    _HOOK_INTERPRETER_RE,
    _ROOT_HOME_RE,
    _RUNTIME_USER_RE,
    _XDG_PREFIX_RE,
    _hook_names,
    _user_writable_target,
    install_script_findings,
    partial_install_files,
)
from ._hygiene import (
    _ANSI_ESCAPE_RE,
    _BUILD_CACHE_RE,
    _CACHE_ENV_RE,
    _DISGUISABLE_COMMANDS,
    _EXECUTABLE_MODE,
    _SPLICE_RE,
    _added_raw_lines,
    _ansi_decode,
    _build_hygiene_findings,
    _desplice,
    _splicing_findings,
    capability_in_diff,
    diff_structure_findings,
)
from ._provenance import (
    _PREBUILT_SUFFIX,
    _TRUSTED_SOURCE_BUCKETS,
    _URL_SCALAR_RE,
    _declared_upstream_host,
    _declared_upstream_url,
    _forge_owner_repo,
    _fork_source_divergence,
    _head_upstream_host,
    _head_upstream_text,
    _prebuilt_host_divergence,
    _registered_domain,
    _source_divergence_allow,
    _upstream_domain_typosquat,
    unchanged_upstream_host,
)
from ._signing import (
    _LFS_OID_RE,
    _SUBMODULE_COMMIT_RE,
    _VALIDPGPKEYS_ENTRY_RE,
    _VALIDPGPKEYS_LINE_RE,
    _signing_key_findings,
    _unread_carrier_findings,
)

__all__ = ['NETWORK_CLIENT', '_ANSI_ESCAPE_RE', '_BINARY_ARTIFACT_RE', '_BUILD_CACHE_RE', '_CACHE_ENV_RE', '_CHECKSUM_ADDED_RE', '_CHECKSUM_ARRAY_NAMES', '_CHECKSUM_EMPTIED_RE', '_CHECKSUM_REMOVED_LINE_RE', '_CHECKSUM_SKIP_RE', '_CHECKSUM_STRENGTH', '_DISGUISABLE_COMMANDS', '_EXECUTABLE_MODE', '_FETCH_IN_PACKAGE_RE', '_HARDENING_OPTIONS', '_HOME_PREFIX_RE', '_HOOK_INTERPRETER_RE', '_INTERPRETER_FETCH', '_INTERPRETER_FETCH_RE', '_LFS_OID_RE', '_PREBUILT_SUFFIX', '_ROOT_HOME_RE', '_RUNTIME_USER_RE', '_SCHEME_MARKERS', '_SPLICE_RE', '_SUBMODULE_COMMIT_RE', '_TRUSTED_BUCKETS', '_TRUSTED_SOURCE_BUCKETS', '_URL_SCALAR_RE', '_VALIDPGPKEYS_ENTRY_RE', '_VALIDPGPKEYS_LINE_RE', '_WW_DIR_RE', '_XDG_PREFIX_RE', '_added_raw_lines', '_ansi_decode', '_build_findings', '_build_flag_findings', '_build_hygiene_findings', '_crossfire_findings', '_declared_upstream_host', '_declared_upstream_url', '_delivery_findings', '_dependency_findings', '_desplice', '_dlagents_override_findings', '_epoch_findings', '_family_values', '_first_insertion_index', '_forge_owner_repo', '_fork_source_divergence', '_function_shadow_findings', '_head_upstream_host', '_head_upstream_text', '_hook_names', '_ioc_findings', '_ip_literal_hosts', '_is_checksum_array', '_is_subsequence', '_line_has_scheme', '_moved_git_ref_findings', '_package_fetch_client', '_persistence_findings', '_post_diff_lines', '_prebuilt_host_divergence', '_raw_targets', '_reconstruction_findings', '_registered_domain', '_removed_declarations', '_require_content_change', '_sabotage_findings', '_signing_key_findings', '_skip_positions', '_source_divergence_allow', '_splicing_findings', '_structural_findings', '_unread_carrier_findings', '_upstream_domain_typosquat', '_url_domain', '_url_host', '_user_writable_target', '_userinfo_urls', 'addendum4_findings', 'any_version_scalar_moved', 'array_order_changes', 'capability_in_diff', 'checksum_array_parity_in_text', 'diff_structure_findings', 'find_line_in_diff', 'install_hook_transition', 'install_script_findings', 'is_skip_justified', 'isolated_checksum_insertion', 'map_diff_lines', 'parse_diff_lines', 'parse_recipe', 'partial_install_files', 'pinning_lost', 're', 'recipe_checksum_parity_finding', 'recipe_states', 'source_array_has_command_substitution', 'source_name_host_swaps', 'split_lines', 'stamp', 'strip_comment', 'unchanged_upstream_host']
