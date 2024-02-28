pipeline {
 	agent none
 	tools {
		maven "Maven 3.9.0"
		jdk "Graal JDK 21" 
	}
	
	environment {
	    /* Constants / Configuration */
	    BUILD_PROPERTIES_ID = "b60f3998-d8fd-434b-b3c8-ed52aa52bc2e"
	    MAVEN_CONFIG_ID = "14324b85-c597-44e8-a575-61f925dba528"
	}

	stages {
		stage ("Npm2MvnPackages and Installers") {
			parallel {
				stage ("WindowsNpm2Mvn Packagers And Installers") {
					agent {
						label "windows && install4j"
					}
					steps {
					
						script {
							env.FULLVERSION = getFullVersion()
							echo "Full Version : ${env.FULLVERSION}"
						}
						
						/* Build windows installers */
						configFileProvider([
					 			configFile(
					 				fileId: "${env.BUILD_PROPERTIES_ID}",  
					 				replaceTokens: true,
					 				targetLocation: "jadaptive.build.properties", 
					 				variable: "BUILD_PROPERTIES"
					 			)
					 		]) {
					 		withMaven(
					 			options: [
					 				artifactsPublisher(fingerprintFilesDisabled: true, archiveFilesDisabled: true)
					 			],
					 			globalMavenSettingsConfig: "${env.MAVEN_CONFIG_ID}"
					 		) {
					 		  	bat 'mvn ' +
					 		  	    '-U -Pinstallers  -Dbuild.projectProperties="%BUILD_PROPERTIES%" ' +
					 		  	    '-Dinstall4j.mediaTypes=windows,windowsArchive ' +
					 		  	    'clean package'					 		  	
					 		}
        				}
        				
        				/* Stash installers */
	        			stash includes: 'target/media/*', name: 'windows-npm2mvn'
	        			
	        			/* Stash updates.xml */
	        			dir('target/media') {
							stash includes: 'updates.xml', name: 'windows-npm2mvn-updates-xml'
	        			}
					}
				}
				
				stage ("Linux Npm2Mvn Packages And Installers") {
					agent {
						label "linux"
					}
					steps {
					
						script {
							env.FULLVERSION = getFullVersion()
							env.PACKAGEVERSION = getPackageVersion()
							echo "Full Version : ${env.FULLVERSION}"
						}
						
                        /* Build linux installers */
                        configFileProvider([
                                configFile(
                                    fileId: "${env.BUILD_PROPERTIES_ID}",  
                                    replaceTokens: true,
                                    targetLocation: "jadaptive.build.properties", 
                                    variable: "BUILD_PROPERTIES"
                                )
                            ]) {
                            withMaven(
                                options: [
                                    artifactsPublisher(fingerprintFilesDisabled: true, archiveFilesDisabled: true)
                                ],
                                globalMavenSettingsConfig: "${env.MAVEN_CONFIG_ID}"
                            ) {
                                sh 'mvn ' +
                                    '-U -Pinstallers  -Dbuild.projectProperties="$BUILD_PROPERTIES" ' +
                                    '-Dinstall4j.disableSigning=true ' +
                                    '-Dinstall4j.mediaTypes=unixInstaller,unixArchive,linuxRPM,linuxDeb ' +
                                    'clean package'                             
                            }
                        }
                        
                        /* Stash installers */
                        stash includes: 'target/media/*', name: 'linux-npm2mvn'
                        
                        /* Stash updates.xml */
                        dir('target/media') {
                            stash includes: 'updates.xml', name: 'linux-npm2mvn-updates-xml'
                        }
                    }
				}
				
				stage ("Mac OS Npm2Mvn Packages And Installers") {
					agent {
						label "macos"
					}
					steps {
					
						script {
							env.FULLVERSION = getFullVersion()
							echo "Full Version : ${env.FULLVERSION}"
						}
						
						/* Build Mac OS secure node */
                        configFileProvider([
                                configFile(
                                    fileId: "${env.BUILD_PROPERTIES_ID}",  
                                    replaceTokens: true,
                                    targetLocation: "jadative.build.properties", 
                                    variable: "BUILD_PROPERTIES"
                                )
                            ]) {
                            withMaven(
                                options: [
                                    artifactsPublisher(fingerprintFilesDisabled: true, archiveFilesDisabled: true)
                                ],
                                globalMavenSettingsConfig: "${env.MAVEN_CONFIG_ID}"
                            ) {
                                sh 'mvn ' +
                                    '-U -Pinstallers  -Dbuild.projectProperties="$BUILD_PROPERTIES" ' +
                                    '-Dinstall4j.mediaTypes=macos,macosFolder,macosArchive,macosFolderArchive ' +
                                    'clean package'                             
                            }
                        }
                        
                        /* Stash installers */
                        stash includes: 'target/media/*', name: 'macos-npm2mvn'
                        
                        /* Stash updates.xml */
                        dir('target/media') {
                            stash includes: 'updates.xml', name: 'macos-npm2mvn-updates-xml'
                        }
        				
					}
				}
			}
		}
		
		stage ('Deploy') {
			agent {
				label 'linux'
			}
			steps {
    			
    			/* Clean everything */
    			withMaven(
		 			globalMavenSettingsConfig: "${env.MAVEN_CONFIG_ID}",
		 		) {
					sh 'mvn clean'
		 		}
			
				script {
					env.FULLVERSION = getFullVersion()
					env.PACKAGEVERSION = getPackageVersion()
					echo "Full Version : ${env.FULLVERSION}"
				}
				
				/* Unstash  installers */
	 		  	unstash 'windows-npm2mvn'
	 		  	unstash 'linux-npm2mvn'
	 		  	unstash 'macos-npm2mvn'
	 		  	
				/* Unstash  updates.xml */
	 		  	dir('npm2mvn/target/media-macos') {
	 		  		unstash 'macos-npm2mvn-updates-xml'
    			}
	 		  	dir('npm2mvn/target/media-windows') {
	 		  		unstash 'windows-npm2mvn-updates-xml'
    			}
	 		  	dir('npm2mvn/target/media-linux') {
	 		  		unstash 'linux-npm2mvn-updates-xml'
    			}
    			
    			/* Merge all updates.xml into one */
    			withMaven(
		 			globalMavenSettingsConfig: "${env.MAVEN_CONFIG_ID}",
		 		) {
					sh 'mvn -P merge-installers com.sshtools:updatesxmlmerger-maven-plugin:merge'
		 		}
		 		
    			/* Upload all installers and updates.xml for this build number */
		 		s3Upload(
		 			consoleLogLevel: 'INFO', 
		 			dontSetBuildResultOnFailure: false, 
		 			dontWaitForConcurrentBuildCompletion: false, 
		 			entries: [[
		 				bucket: 'sshtools-public/npm2mvn/' + env.FULLVERSION, 
		 				noUploadOnFailure: true, 
		 				selectedRegion: 'eu-west-1', 
		 				sourceFile: 'npm2mvn/target/media/*', 
		 				storageClass: 'STANDARD', 
		 				useServerSideEncryption: false]], 
		 			pluginFailureResultConstraint: 'FAILURE', 
                    profileName: 'JADAPTIVE Buckets', 
		 			userMetadata: []
		 		)
		 		
    			/* Copy the merged updates.xml to the continuous directory so updates can be seen
    			by anyone on this channel */
		 		s3Upload(
		 			consoleLogLevel: 'INFO', 
		 			dontSetBuildResultOnFailure: false, 
		 			dontWaitForConcurrentBuildCompletion: false, 
		 			entries: [[
		 				bucket: 'sshtools-public/npm2mvn/continuous', 
		 				noUploadOnFailure: true, 
		 				selectedRegion: 'eu-west-1', 
		 				sourceFile: 'npm2mvn/target/media/updates.xml', 
		 				storageClass: 'STANDARD', 
		 				useServerSideEncryption: false]], 
		 			pluginFailureResultConstraint: 'FAILURE', 
                    profileName: 'JADAPTIVE Buckets', 
		 			userMetadata: []
		 		)
			}					
		}			
	}
}

/* Create full version number from Maven POM version and the build number
 *
 * TODO make into a reusable library - https://stackoverflow.com/questions/47628248/how-to-create-methods-in-jenkins-declarative-pipeline
 */
String getFullVersion() {
	def pom = readMavenPom file: "pom.xml"
	pom_version_array = pom.version.split('\\.')
	suffix_array = pom_version_array[2].split('-')
	return pom_version_array[0] + '.' + pom_version_array[1] + "." + suffix_array[0] + "-${BUILD_NUMBER}"
}

/* Create full version number from Maven POM version and the build number for use in the Debian
 * package version which differs slightly from full verison
 *
 * TODO make into a reusable library - https://stackoverflow.com/questions/47628248/how-to-create-methods-in-jenkins-declarative-pipeline
 */
String getPackageVersion() {
	def pom = readMavenPom file: "pom.xml"
	pom_version_array = pom.version.split('\\.')
	suffix_array = pom_version_array[2].split('-')
	return pom_version_array[0] + '_' + pom_version_array[1] + "_" + suffix_array[0] + "-${BUILD_NUMBER}"
}
