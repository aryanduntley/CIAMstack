# PingFederate node files (synthetic)

Made-up copies of the source PingFederate nodes' own files (one folder per node, named by its hostname), read by `opsdir import --change CHG-2008 pingfederate/node-files exports/pingfederate-nodes`: each node's operational mode, tags and listeners go on its server, the cluster's discovery (NATIVE_S3_PING) is checked against the source's `pf-cluster-discovery` binding, and hivemodule.xml says OAuth clients and grants are kept in JDBC.
