// Local immutable SCM snapshot -> native Linux test runner. No live VPN deployment.
pipeline {
    agent none
    options {
        skipDefaultCheckout(true)
        timestamps()
        disableConcurrentBuilds()
        timeout(time: 60, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '20'))
    }
    parameters {
        string(name: 'SOURCE_SHA', defaultValue: '', description: 'Required full immutable tunnel commit SHA; must match this job SCM revision')
    }
    stages {
        stage('Immutable sources') {
            agent { label 'built-in' }
            steps {
                script {
                    if (!(params.SOURCE_SHA ==~ /[0-9a-f]{40}/)) error('SOURCE_SHA must be a full commit SHA')
                    deleteDir()
                    def revision = checkout scm
                    if (revision.GIT_COMMIT != params.SOURCE_SHA) error('SCM revision differs from requested SHA')
                }
                sh '''
                    set -eu
                    mkdir -p reports .client-source
                    test "$(git rev-parse HEAD)" = "$SOURCE_SHA"
                    printf '%s\n' "$SOURCE_SHA" > reports/source-sha.txt
                    client_sha=4400ca12938619df92326c4abe21818bf39915e9
                    git -C /Users/onixus/Git/R-Trusttunnel cat-file -e "$client_sha^{commit}"
                    git -C /Users/onixus/Git/R-Trusttunnel archive "$client_sha" | tar -xf - -C .client-source
                    printf '%s\n' "$client_sha" > reports/client-source-sha.txt
                '''
                stash name: 'immutable-sources', includes: '**', excludes: '.git/**', useDefaultExcludes: false
            }
        }
        stage('Full server gate') {
            agent { label 'gaming-amd64' }
            steps {
                deleteDir()
                unstash 'immutable-sources'
                sh '''
                    set -eu
                    test "$(cat reports/source-sha.txt)" = "$SOURCE_SHA"
                    docker build -f ci/Dockerfile -t "tunnel-ci:$BUILD_NUMBER" .
                    docker image inspect --format '{{.Id}}' "tunnel-ci:$BUILD_NUMBER" > reports/test-image.txt
                    mkdir -p .ci-tmp
                    docker run --rm --network host --shm-size=1g \
                        -v "$WORKSPACE:$WORKSPACE:z" -w "$WORKSPACE" \
                        -v tunnel-server-ci-target:/ci-target \
                        -e CARGO_TARGET_DIR=/ci-target \
                        -e "TMPDIR=$WORKSPACE/.ci-tmp" \
                        "tunnel-ci:$BUILD_NUMBER" bash ci/test-server.sh container
                    # Run Docker fixture orchestration on the agent; the test
                    # container does not need access to the host Docker socket.
                    python3 -m venv .acceptance-venv
                    .acceptance-venv/bin/pip install -r server/test-environment/requirements.txt
                    TMPDIR="$WORKSPACE/.ci-tmp" \
                        PATH="$WORKSPACE/.acceptance-venv/bin:$PATH" \
                        CARGO_TARGET_DIR="$WORKSPACE/.acceptance-bin" \
                        bash ci/test-server.sh acceptance
                '''
            }
            post {
                always {
                    junit testResults: 'reports/*.xml', allowEmptyResults: true
                    archiveArtifacts artifacts: 'reports/**,test-results/**', allowEmptyArchive: false, fingerprint: true
                }
            }
        }
    }
}
