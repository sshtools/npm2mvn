# ![NPM](src/web/npm.png "NPM") 2 ![Maven](src/web/maven.png "Maven")

A simple proxy that makes [Npm](https://www.npmjs.com/) packages appear as if they are [Maven](https://mvnrepository.com/repos/central) artifacts.

The intended use for this is including Javascript resources such as Jquery, Bootstrap,
and more in Java web applications.

You can just add npm packages as ordinary Maven dependencies and have Maven download
and cache them for you, as well as adding the Jars to your classpath for accessing
the resources.

See the [Wiki](https://github.com/sshtools/npm2mvn/wiki) for more information. 

## Status

Npm2Mvn is currently still in its alpha-stage, but we hope to rapidly bring it up
to beta, then release quality.

In the mean-time though, we have an experimental public repository 
at https://npm2mvn.jadaptive.com that you can try out, or host your own by downloading
one of our pre-release self-updating installers.

Of course, you can always clone the source and build your own server. Is is even fully
compatible with Graal Native Image for fast startup and low resource usage.

## TODO

Npm2Mvn is currently under development. 

 * Locking for multi-user usage
 * Configurable cache
 * Cache misses
