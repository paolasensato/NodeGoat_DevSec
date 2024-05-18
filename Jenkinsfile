pipeline {
    agent any

    stages {
        stage('List Software Versions') {
            steps {
                script {
                    echo 'Listing Java version'
                    sh 'java -version'
                    
                    echo 'Listing Docker version'
                    sh 'docker --version'
                }
            }
        }
        stage('Checkout') {
            steps {
                script {
                    echo 'Checking out the project'
                    git 'https://github.com/OWASP/NodeGoat.git'  // Substitua pelo URL do seu repositório
                }
            }
        }
    }
}
