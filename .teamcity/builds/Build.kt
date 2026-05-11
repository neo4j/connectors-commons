package builds

import jetbrains.buildServer.configs.kotlin.Project
import jetbrains.buildServer.configs.kotlin.sequential
import jetbrains.buildServer.configs.kotlin.toId
import jetbrains.buildServer.configs.kotlin.triggers.vcs

class Build(
    name: String,
    branchFilter: String,
    forPullRequests: Boolean,
    triggerRules: String? = null
) :
    Project({
      this.id(name.toId())
      this.name = name

      val complete = Empty("${name}-complete", "complete")

      val bts = sequential {
        if (forPullRequests)
            buildType(WhiteListCheck("${name}-whitelist-check", "white-list check"))
        if (forPullRequests) dependentBuildType(PRCheck("${name}-pr-check", "pr check"))
        parallel {
          dependentBuildType(SemgrepCheck("${name}-semgrep-check", "semgrep check"))

          JavaVersion.entries.forEach { java ->
            sequential {
              dependentBuildType(
                  Maven(
                      "${name}-build-${java.version}",
                      "build - java ${java.version}",
                      "sortpom:verify license:check spotless:check compile",
                      "-DspotlessFiles=src/main/java/.*.java",
                      java))
              dependentBuildType(
                  Maven(
                      "${name}-test-${java.version}",
                      "test - java ${java.version}",
                      "verify",
                      javaVersion = java,
                      size = LinuxSize.LARGE))
            }
          }
        }
        dependentBuildType(complete)
        if (!forPullRequests)
            collectArtifacts(dependentBuildType(Release("${name}-release", "release")))
      }

      bts.buildTypes().forEach {
        it.thisVcs()

        it.features {
          loginToECR()
          enableCommitStatusPublisher()
          if (forPullRequests) enablePullRequests()
        }

        buildType(it)
      }

      complete.triggers {
        vcs {
          this.branchFilter = branchFilter
          this.triggerRules = triggerRules
        }
      }
    })
