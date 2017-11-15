Installing Anchore CLI from source
==================================

The Anchore grafeas CLI can be installed from source using the Python
pip utility. The utility connects to an existing anchore-engine DB and
constructs grafeas note and occurrence documents.  Below is an example
installation if, say, one were running a fresh container based on
centos:latest

.. code::

    yum -y install epel-release && yum -y install python-pip git && pip install --upgrade pip && pip install --upgrade setuptools

    git clone https://github.com/anchore/anchore-grafeas-cli
    cd anchore-grafeas-cli
    pip install --upgrade . 
    cd ..

Using Anchore Grafeas CLI
==================================

The pre-requisites for using this tool are that there is an existing
anchore-engine service up and running, along with the anchore-engine
database port exposed and accessible from the place where this tool is
being executed.  Note that if you are running anchore-engine using the
supplied docker-compose.yaml, you will have to add a section to the
anchore-db service (and restart the services) to expose the DB port
5432 in order for it to be accessed externally.  If you do not have
anchore-engine service running already, please visit the
[anchore-engine github
page](https://github.com/anchore/anchore-engine) for instructions on
how to install anchore-engine.

Once anchore-engine is up and running (we also recommend adding some
images to anchore-engine, in order to get package notes and
package-vulnerability occurrences), the general flow is to set the
ANCHORE_DB_CONNECT environment to the connect string for the
anchore-engine DB, and then use the tool to list and then generate
vulnerability/package note JSON documents.  To generate grafeas
package-vulnerability occurrences, set GRAFEAS_HOSTPORT environment to
an accessible grafeas service, and then use the tool to list and then
generate package-vulnerability occurrence JSON documents.

.. code::

    export ANCHORE_DB_CONNECT="postgresql+pg8000://postgres:<your-anchore-db-password>@<your-anchore-db-host>:5432/postgres"
    anchore-grafeas note vulnerabilities
    anchore-grafeas note vulnerabilities <vulnerabilityId from previous>
    anchore-grafeas note packages
    anchore-grafeas note packages <packageName from previous>

    export GRAFEAS_HOSTPORT="<your-grafeas-host>:8080"
    anchore-grafeas occurrence package-vulnerabilities
    anchore-grafeas occurrence package-vulnerabilities <full line (imageId packageName vulnId) from previous>

Examples with curl uploads to grafeas service (for the 'nash' package in this example)

.. code::

    anchore-grafeas note packages nash | curl -v -H 'content-type: application-json' -XPOST http://${GRAFEAS_HOSTPORT}/v1alpha1/projects/anchore-distro-packages/notes?noteId=nash -d @-
    anchore-grafeas note packages nash | curl -v -H 'content-type: application-json' -XPUT http://${GRAFEAS_HOSTPORT}/v1alpha1/projects/anchore-distro-packages/notes/nash -d @-
    curl -v -XGET http://${GRAFEAS_HOSTPORT}/v1alpha1/projects/anchore-distro-packages/notes/nash    
    curl -v -XDELETE http://${GRAFEAS_HOSTPORT}/v1alpha1/projects/anchore-distro-packages/notes/nash
