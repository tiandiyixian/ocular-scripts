#!/bin/sh

IFS="
"

out() {
    first=yes
    sort | uniq | while read -r line; do
        if [ -n "$first" ]; then
            first=
        else
            printf ","
        fi
        echo "$line"
    done
}

echo "{\"dependencies\": ["

if ls *.gradle 1>/dev/null 2>&1; then
    projects=`gradle projects 2>&1 | grep -- "--- " | cut -d" " -f5`
    if [ -z "$projects" ]; then
        projectDeps=`gradle dependencies --configuration testRuntime 2>&1 | grep -Eo -- "--- (.+)" | grep -v "project :" | cut -c5- | cut -d" " -f1,3`
        for projectDep in $projectDeps; do
            depTuple=`echo "$projectDep" | cut -d" " -f1`

            depGroup=`echo "$depTuple" | cut -d: -f1`
            depName=`echo "$depTuple" | cut -d: -f2`
            depVersion=`echo "$depTuple" | cut -d: -f3`

            wins=`echo "$projectDep" | cut -s -d" " -f2`
            if [ -n "$wins" ]; then
                depVersion="$wins"
            fi

            echo "{\"group\": \"$depGroup\", \"name\": \"$depName\", \"version\": \"$depVersion\"}"
        done
    else
        for project in $projects; do
            projectDeps=`gradle $project:dependencies --configuration testRuntime 2>&1 | grep -Eo -- "--- (.+)" | grep -v "project :" | cut -c5- | cut -d" " -f1,3`
            for projectDep in $projectDeps; do
                depTuple=`echo "$projectDep" | cut -d" " -f1`

                depGroup=`echo "$depTuple" | cut -d: -f1`
                depName=`echo "$depTuple" | cut -d: -f2`
                depVersion=`echo "$depTuple" | cut -d: -f3`

                wins=`echo "$projectDep" | cut -s -d" " -f2`
                if [ -n "$wins" ]; then
                    depVersion="$wins"
                fi

                echo "{\"group\": \"$depGroup\", \"name\": \"$depName\", \"version\": \"$depVersion\"}"
            done
        done
    fi | out
elif [ -f pom.xml ]; then
    projectDeps=`mvn -B dependency:list -Dsort=true | grep "^\[INFO\]    " | awk '{print $2}' | grep -v none | cut -d: -f1,2,4`
    for depTuple in $projectDeps; do
        depGroup=`echo "$depTuple" | cut -d: -f1`
        depName=`echo "$depTuple" | cut -d: -f2`
        depVersion=`echo "$depTuple" | cut -d: -f3`

        echo "{\"group\": \"$depGroup\", \"name\": \"$depName\", \"version\": \"$depVersion\"}"
    done | out
fi

echo "]}"
