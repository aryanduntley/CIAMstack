"""What changes between OpenDJ releases (contract.VersionChange; milestone 86), from the project's release notes
(research 2373): 4.x to 5.x keeps the commands and options the render uses; 5.1.2 changes the storage formats. Data."""
from opsdir.core.contract import VersionChange

VERSION_CHANGES = (
    VersionChange(">=5.1.2", "the JE backend and changelog formats change, and indexes must be rebuilt", "the "
                  "directory's data and replication changelog", "action", "Load the target's data from LDIF (or run "
                  "upgrade, then rebuild every index) and initialise replication before the cutover; plan the time "
                  "a full rebuild takes."),
)
