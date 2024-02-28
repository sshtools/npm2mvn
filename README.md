# Npm2Mvn

A simple proxy that makes Npm packages appear as it they are Maven artifacts.

The intended use for this is including Javascript resources such as Jquery, Bootstrap,
and more in Java web applications.

You can just add npm packages as ordinary Maven dependencies and have Maven download
and cache them for you, as well as adding the Jars to your classpath for accessing
the resources.

More to follow .. 

## Who Is This For?

 * You are writing a Maven based Java web application and want to use Javascript resources that
   are available via Npm. 

## TODO

 * Locking for multi-user usage
 * Configurable cache
 * Add dependencies to generated POMs