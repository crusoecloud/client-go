#!/bin/bash

GO_DOC_PAGE_PREFIX="doc"
GO_DOC_HTML_OUTPUT="public/${GO_DOC_PAGE_PREFIX}"
GO_DOC_HTTP="localhost:6060"

if [ -z "${GO_MODULE:=}" ]; then
    GO_MODULE=`go list -m`
fi

go_doc_update() {
    # Update generated Go source code documentation
    # Add URI query for GitLab searching
    INPUTS=""
    INPUTS="${INPUTS}<input type=\"hidden\" name=\"utf8\" value=\"✓\">"
    INPUTS="${INPUTS}<input type=\"hidden\" name=\"group_id\" value=\"\">"
    INPUTS="${INPUTS}<input type=\"hidden\" name=\"project_id\" value=\"${CI_PROJECT_ID:=}\">"
    INPUTS="${INPUTS}<input type=\"hidden\" name=\"nav_source\" value=\"navbar\">"
    INPUTS="${INPUTS}<input type=\"hidden\" name=\"search_code\" value=\"true\">"
    INPUTS="${INPUTS}<input type=\"hidden\" name=\"repository_ref\" value=\"${CI_DEFAULT_BRANCH:=}\">"

    # Defines basic documentation URLs
    CI_PAGES_URL="${CI_PAGES_URL:=}"
    GO_DOC_PAGE_PREFIX="${GO_DOC_PAGE_PREFIX:=}"
    GO_DOC_HTML_OUTPUT="${GO_DOC_HTML_OUTPUT:=}"

    MAIN_URL="${CI_PAGES_URL}/${GO_DOC_PAGE_PREFIX}"
    MODULE_URL="${MAIN_URL}/pkg/${GO_MODULE}/"

    echo "Updating generated HTML documentation..."

    # Update all HTML files
    find "${GO_DOC_HTML_OUTPUT}" -name '*.html' -exec sed -i \
        -e "s,http://${GO_DOC_HTTP}/search,${CI_SERVER_URL:=}/search,g" \
        -e 's/\(<span\s\+class="search-box">.*\s\+name=\)"q"/\1"search"/' \
        -e "s,<span\s\+class=\"search-box\">,\0${INPUTS},g" \
        -e "s,\"http://${GO_DOC_HTTP}/pkg/\",\"${MODULE_URL}\",g" \
        -e "s,http://${GO_DOC_HTTP},${MAIN_URL},g" \
        {} +

    echo "Generated HTML documentation updated"
}

create_redirect_html() {
    # Creating html file with redirection
    FILE="${1}"
    URL="${2}"

    if [ ! -f "${FILE}" ]; then
        echo "Generating ${FILE} file..."

        # Create directory
        mkdir -p "$(dirname "${FILE}")"

        # Creating html file with redirection
        cat <<-EOF > "${FILE}"
<!DOCTYPE HTML>
<html lang="en-US">
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="refresh" content="0; url=${URL}">
        <script type="text/javascript">
            window.location.href = "${URL}"
        </script>
        <title>Page Redirection</title>
    </head>
    <body>
        If you are not redirected automatically, follow this <a href='${URL}'>link</a>.
    </body>
</html>
EOF
    fi
}

printf '\e[1;36m%s\e[0m\n' "Generating Go documentation..."

# Local URL to scrape (includes unexported objects)
URL="http://${GO_DOC_HTTP}/pkg/${GO_MODULE}/?m=all"

rm -rf "${GO_DOC_HTML_OUTPUT}"

# Start godoc server
echo "Starting godoc server..."
godoc -http="${GO_DOC_HTTP}" &
PID=$!

# Wait for godoc server to start up
while ! curl --fail --silent "${URL}" >/dev/null 2>&1; do
	sleep 0.1
done

STATUS=0

# Scrape all docs for this module
wget \
	--recursive \
	--no-verbose \
	--convert-links \
	--page-requisites \
	--execute=robots=off \
	--include-directories="/lib,/pkg/${GO_MODULE},/src/${GO_MODULE}" \
	--exclude-directories="*" \
	--directory-prefix="public/doc" \
	--no-host-directories \
	--no-parent \
	"${URL}" || STATUS=$?

# Drop the query parameters from filenames (only keep the ?m=all versions of pages)
find ${GO_DOC_HTML_OUTPUT} -type f -name "*\?*" -print0 | 
while IFS= read -r -d '' file; 
do 
    mv -f "$file" "`echo $file | cut -d? -f1`"; 
done

kill -9 "${PID}"
echo "Stopped godoc server"

# Update generated Go source code documentation
go_doc_update

# Creating the index.html file with redirection to documentation page
create_redirect_html \
    "${CI_PROJECT_DIR:=}/public/index.html" \
    "${CI_PAGES_URL}/${GO_DOC_PAGE_PREFIX}/pkg/${GO_MODULE}/"

if [ "${STATUS:-0}" -ne 0 ] && [ "${STATUS:-0}" -ne 8 ]; then
	printf '\e[1;31m%s\e[0m\n' "The godoc server failed"
	exit 1
fi

printf '\e[1;32m%s\e[0m\n' "Go documentation generated"
