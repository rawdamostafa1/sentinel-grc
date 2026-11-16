"""Loads everything in the right order. Run: python seed_all.py

  python seed_all.py              assets, controls, risks            (what GRC owns; safe to repeat)
  python seed_all.py --demo       ... plus demo incidents, findings, alerts, actions, policies, compliance snapshot
  python seed_all.py --remove-demo   remove only the demo (fixture) documents
Demo documents are marked source="fixture", so real data from the other owners is never touched.
"""
import sys

import seed
import seed_controls
import seed_demo
import seed_findings
import seed_incidents
import seed_risks


def main(argv=None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    if "--remove-demo" in argv:
        seed_demo.remove()
        return
    seed.run()
    seed_controls.run()
    seed_risks.run()
    if "--demo" in argv:
        seed_incidents.run()
        seed_findings.run()
        seed_demo.run()
    print("Done. Check the result with: python check_db.py")


if __name__ == "__main__":
    main()
