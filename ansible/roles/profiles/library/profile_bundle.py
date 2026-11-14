#!/usr/bin/python
"""Ansible's sole local profile-bundle consumer."""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.profile_bundle import Invalid, render, write_bundle


def main():
    module = AnsibleModule(argument_spec={"topology": {"type": "dict", "required": True}, "credentials": {"type": "dict", "required": True, "no_log": True}, "output_dir": {"type": "path", "required": True}}, supports_check_mode=True)
    try:
        identity, files = render(module.params["topology"], module.params["credentials"])
        changed = write_bundle(module.params["output_dir"], identity, files, module.check_mode)
    except (Invalid, OSError, ValueError, TypeError, KeyError):
        # Detailed constraints are exercised directly in unit tests. Module input
        # includes credentials: even Python/Ansible exception rendering is private.
        module.fail_json(msg="Profile bundle rejected; check the documented topology, ACL and credential constraints (values redacted)")
    module.exit_json(changed=changed, bundle_id=identity, candidate=module.params["output_dir"] + "/candidate", usable=False)


if __name__ == "__main__":
    main()
