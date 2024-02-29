package com.sshtools.npm2mvn;

import static java.nio.file.Files.createDirectories;
import static java.text.MessageFormat.format;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.json.Json;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.slf4j.bridge.SLF4JBridgeHandler;

import com.sshtools.tinytemplate.Templates.TemplateModel;
import com.sshtools.tinytemplate.Templates.TemplateProcessor;
import com.sshtools.uhttpd.UHTTPD;
import com.sshtools.uhttpd.UHTTPD.NCSALoggerBuilder;
import com.sshtools.uhttpd.UHTTPD.Status;
import com.sshtools.uhttpd.UHTTPD.Transaction;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.IVersionProvider;
import picocli.CommandLine.Option;

@Command(name = "npm2mvn", mixinStandardHelpOptions = true, description = "Npm to Maven proxy.", versionProvider = Npm2Mvn.Version.class)
public class Npm2Mvn implements Callable<Integer> {
	
	static {
        SLF4JBridgeHandler.removeHandlersForRootLogger();
        SLF4JBridgeHandler.install();
	}
	
	private final static List<String> STRIP_PREFIXES = Arrays.asList(
			"package/dist/", 
			"package/");
	
	private final static Logger LOG = Logger.getLogger(Npm2Mvn.class.getName());
	private final static int DEFAULT_HTTP_PORT = 9080;
	private final static URI root = URI.create("https://registry.npmjs.org");

	private final class TeeInputStream extends FilterInputStream {
		private final OutputStream out;

		private TeeInputStream(InputStream in, OutputStream out) {
			super(in);
			this.out = out;
		}

		@Override
		public void close() throws IOException {
			try {
				super.close();
			} finally {
				out.close();
			}	
		}

		@Override
		public int read() throws IOException {
			var r = in.read();
			if(r != -1) {
				out.write(r);
			}
			return r;
		}

		@Override
		public int read(byte[] b, int off, int len) throws IOException {
			var r = in.read(b, off, len);
			if(r > 0) {
				out.write(b, off, r);
			}
			return r;
		}
	}

	final static class Version implements IVersionProvider {

		@Override
		public String[] getVersion() throws Exception {
			return new String[] { System.getProperty("build.version", "Unknown") };
		}
	}

	public static void main(String[] args) {
		System.exit(new CommandLine(new Npm2Mvn()).execute(args));
	}
	
	@Option(names = {"-p", "--path"}, description = "Root path under which artifacts are served from. If omitted, will be '/'")
	private Optional<String> path;
	
	@Option(names = {"-g", "--group-id"}, description = "The group id to serve all packages as. Defaults to 'npm'")
	private Optional<String> servedGroupId;
	
	@Option(names = {"-C", "--cache-dir"}, description = "The directory where artifacts are cached")
	private Optional<Path> cacheDir;
	
	@Option(names = {"-b", "--bind-address"}, description = "The address to bind to. If not specified, localhost will be used.")
	private Optional<String> bindAddress;
	
	@Option(names = {"-w", "--web-resources"}, description = "A single index.html, as well as any non .html resources will be served from this location.")
	private Optional<Path> webResources;
	
	@Option(names = {"-a", "--access-logs"}, description = "Location of NCSA format access logs. If not supplied, no logs will be generated.")
	private Optional<Path> accessLogs;
	
	@Option(names = {"-P", "--http-port"}, description = "The port on which plain HTTP requests will be accepted.")
	private Optional<Integer> httpPort;
	
	@Option(names = {"-S", "--https-port"}, description = "The port on which HTTPs requests will be accepted.")
	private Optional<Integer> httpsPort;
	
	@Option(names = {"-r", "--resource-path-pattern"}, description = "The pattern to use for paths of resources in generated artifacts. Default is '%%g/%%a/%%v`. %%g is replaced the group Id, %%a is replaced by the artifact Id, and %%v is replaced by the version.")
	private Optional<String> resourcePathPattern;
	
	@Option(names = {"-K", "--keystore-file"}, description = "The path to the keystore. Uses $HOME/.keystore if not specified.")
	private Optional<Path> keystoreFile;
	
	@Option(names = {"-W", "--keystore-password"}, description = "The password for the keystore. Defaults to changeit.")
	private Optional<String> keystorePassword;
	
	@Option(names = {"-k", "--key-password"}, description = "The password for the key. Defaults to changeit.")
	private Optional<String> keyPassword;
	
	@Option(names = {"-T", "--keystore-type"}, description = "The type of keystore.")
	private Optional<String> keystoreType;
	
	private final TemplateProcessor processor;
	
	public Npm2Mvn() {
		processor = new TemplateProcessor.Builder().
				build();
	}

	@Override
	public Integer call() throws Exception {
		var bldr = UHTTPD.server();
		
		/* Ports and address */
		
		var http = httpPort();
		var https = httpsPort();
		var bindAddress = optionalString(this.bindAddress, "bindAddress");
		
		if(http.isEmpty() && https.isEmpty()) {
			LOG.info("Neither http or https specific ports supplie, falling back to http only on port " + DEFAULT_HTTP_PORT);
			bldr.withHttp(DEFAULT_HTTP_PORT);
		}
		else  {
			http.ifPresent(p -> bldr.withHttp(p));
			https.ifPresent(p -> { 
				bldr.withHttps(p);
				bindAddress.ifPresent(addr-> bldr.withHttpsAddress(addr));
			});
			optionalPath(keystoreFile, "keystoreFile").ifPresent(bldr::withKeyStoreFile);
			optionalString(keystorePassword, "keystorePassword").ifPresent(pw -> bldr.withKeyStorePassword(pw.toCharArray()));
			optionalString(keyPassword, "keyPassword").ifPresent(pw -> bldr.withKeyPassword(pw.toCharArray()));
			optionalString(keystoreType, "keystoreType").ifPresent(bldr::withKeyStoreType);
		}
		bindAddress.ifPresent(addr-> bldr.withHttpAddress(addr));
		
		/* Mappings */
		bldr.get(optionalString(path, "path").map(p -> p.endsWith("/") ? p : p + "/").orElse("/") + "(.*)", this::handle);
		bldr.get(".*\\.html", this::homePage);
		bldr.get("/", this::homePage);
		optionalPath(webResources, "webResources").ifPresent(p -> bldr.withFileResources("/(.*)", p));
		bldr.withClasspathResources("/(.*)", getClass().getClassLoader(), "com/sshtools/npm2mvn");
		
		/* Request logs */
		optionalPath(accessLogs, "accessLogs").ifPresent(p -> bldr.withLogger(
			new NCSALoggerBuilder().
				withDirectory(p).
				build()
		));
		
		
		/* Server */
		var srvr = bldr.build();
		LOG.info(format("Caching to {0}", cacheDir()));
		srvr.run();
		
		return 0;
	}
	
	private void homePage(Transaction tx) {
		try(var templ = findHomeTemplate()) {
			tx.response("text/html", processor.process(templ.
					variable("serverUrl", tx.url()).
					variable("groupId", servedGroupId())));
		}
	}

	private TemplateModel findHomeTemplate() {
		var pathOr = optionalPath(webResources, "webResources");
		if(pathOr.isPresent()) {
			var path = pathOr.get().resolve("index.html");
			if(Files.exists(path)) {
				return TemplateModel.ofPath(path);
			}
			
		}
		return TemplateModel.ofResource(Npm2Mvn.class, "index.html");
	}
	
	private Optional<Integer> httpPort() {
		return httpPort.or(() -> Optional.ofNullable(System.getProperty("httpPort", System.getProperty("port"))).map(Integer::parseInt));
	}
	
	private Optional<Integer> httpsPort() {
		return httpsPort.or(() -> Optional.ofNullable(System.getProperty("httpsPort")).map(Integer::parseInt));
	}
	
	private Optional<Path> optionalPath(Optional<Path> path, String key) {
		return path.or(() -> { 
			var res = System.getProperty(key);
			return Optional.ofNullable(res).map(Paths::get); 
		});
	}
	
	private Optional<String> optionalString(Optional<String> value, String key) {
		return value.or(() -> Optional.ofNullable(System.getProperty(key)));
	}
	
	private String servedGroupId() {
		return servedGroupId.orElseGet(() -> System.getProperty("groupId", "npm"));
	}
	
	private String resourcePathPattern() {
		return resourcePathPattern.orElseGet(() -> System.getProperty("resourcePathPattern", "%g/%a/%v"));
	}
	
	private void handle(Transaction tx) {
		var seq = tx.match(0);
		var pathParts = seq.split("/");
		try {
			if(pathParts.length > 3) {
				var filename = pathParts[pathParts.length - 1];
				var version = pathParts[pathParts.length - 2];
				var artifactId = pathParts[pathParts.length - 3];
				var groupId = String.join(".", Arrays.asList(pathParts).subList(0, pathParts.length - 3));
				
				if(!groupId.equals(servedGroupId())) {
					throw new NoSuchFileException(groupId);
				}
				
				if(filename.equals(artifactId + "-" + version + "-javadoc.jar")) {
					throw new NoSuchFileException(filename);
				}
				
				if(filename.equals(artifactId + "-" + version + "-sources.jar")) {
					throw new NoSuchFileException(filename);
				}
				
				LOG.info(format("Request for {0}:{1}:{2} ({3})", groupId, artifactId, version, filename));
				
				if(filename.endsWith(".pom")) {
					tx.response("text/xml", getPom(filename, version, artifactId, groupId));
				}
				else if(filename.endsWith(".jar")) {
					tx.response("application/java-archive", getJar(filename, version, artifactId, groupId));
				}
				else if(filename.endsWith(".pom.sha1")) {
					tx.response("text/plain", getPomSha1(filename, version, artifactId, groupId));
				}
				else if(filename.endsWith(".jar.sha1")) {
					tx.response("text/plain", getJarSha1(filename, version, artifactId, groupId));
				}
				else
					throw new NoSuchFileException(filename);
			}
		}
		catch(NoSuchFileException nsfe) {
			LOG.info(format("Not found. {0}", nsfe.getFile()));
			tx.responseCode(Status.NOT_FOUND);
		}
		catch(Exception e) {
			LOG.log(Level.SEVERE, "Failed to proxy Maven request to Npm.", e);			
			tx.responseCode(Status.INTERNAL_SERVER_ERROR);
		}
		
	}
	
	private Path cacheDir() {
		return this.cacheDir.orElseGet(() -> {
			var cacheDirProp = System.getProperty("cacheDir");
			if(cacheDirProp == null)
				return Paths.get(System.getProperty("user.home")).resolve(".m2").resolve("npm2mvn").resolve("cache");
			else
				return Paths.get(cacheDirProp);
		});
	}
	
	private InputStream getPomSha1(String filename, String version, String artifactId, String groupId) throws IOException, NoSuchAlgorithmException {
		var cacheFileDir = artifactCacheDir(version, artifactId);
		var cacheFile = cacheFileDir.resolve(artifactId + ":" + version + ".pom.sha1");
		if(Files.exists(cacheFile)) {
			LOG.info(format("Responding with POM SHA1 from the cache @", cacheFile));
		}
		else {
			var digest = MessageDigest.getInstance("SHA-1");
			try(var digestIn = new DigestInputStream(getPom(filename, version, artifactId, groupId), digest)) {
				digestIn.transferTo(OutputStream.nullOutputStream());
				try(var wtr = Files.newBufferedWriter(cacheFile)) {
					wtr.write(Hex.encodeHexString(digest.digest()));
					wtr.newLine();
				}
			};
		}
		return Files.newInputStream(cacheFile);
	}
	
	private InputStream getJarSha1(String filename, String version, String artifactId, String groupId) throws IOException, NoSuchAlgorithmException {
		var cacheFileDir = artifactCacheDir(version, artifactId);
		var cacheFile = cacheFileDir.resolve(artifactId + ":" + version + ".sha1");
		if(Files.exists(cacheFile)) {
			LOG.info(format("Responding with SHA1 from the cache @", cacheFile));
		}
		else {
			var digest = MessageDigest.getInstance("SHA-1");
			try(var digestIn = new DigestInputStream(getJar(filename, version, artifactId, groupId), digest)) {
				digestIn.transferTo(OutputStream.nullOutputStream());
				try(var wtr = Files.newBufferedWriter(cacheFile)) {
					wtr.write(Hex.encodeHexString(digest.digest()));
					wtr.newLine();
				}
			};
		}
		return Files.newInputStream(cacheFile);
	}
	
	private InputStream getPom(String filename, String version, String artifactId, String groupId) throws IOException {
		var cacheFileDir = artifactCacheDir(version, artifactId);
		var cacheFile = cacheFileDir.resolve(artifactId + ":" + version + ".pom");
		if(Files.exists(cacheFile)) {
			LOG.info(format("Responding with POM {0} from the cache @", artifactId, cacheFile));
			return Files.newInputStream(cacheFile);
		}
		else {
			var in = downloadManifestAndTransformToPom(filename, version, artifactId, groupId);
			LOG.info(format("Responding with fresh copy of POM {0} from NPM", artifactId));
			var out = Files.newOutputStream(cacheFile);
			return new TeeInputStream(in, out);
		}
	}
	
	private InputStream getJar(String filename, String version, String artifactId, String groupId) throws IOException {
		var cacheFileDir = artifactCacheDir(version, artifactId);
		var cacheFile = cacheFileDir.resolve(artifactId + ":" + version + ".jar");
		if(Files.exists(cacheFile)) {
			LOG.info(format("Responding with Jar {0} from the cache @", artifactId, cacheFile));
			return Files.newInputStream(cacheFile);
		}
		else {
			var in = downloadPackageAndTransformToJar(filename, version, artifactId, groupId);
			LOG.info(format("Responding with fresh copy of transform Jar {0} from NPM", artifactId));
			var out = Files.newOutputStream(cacheFile);
			return new TeeInputStream(in, out);
		}
	}
	
	private InputStream getManifest(String filename, String version, String artifactId, String groupId) throws IOException {
		var cacheFileDir = artifactCacheDir(version, artifactId);
		var cacheFile = cacheFileDir.resolve(artifactId + ":" + version + ".json");
		if(Files.exists(cacheFile)) {
			LOG.info(format("Responding with manifest {0} from the cache @", artifactId, cacheFile));
			return Files.newInputStream(cacheFile);
		}
		else {
			var in = downloadManifest(filename, version, artifactId, groupId);
			LOG.info(format("Responding with fresh copy manifest of {0} from NPM", artifactId));
			var out = Files.newOutputStream(cacheFile);
			return new TeeInputStream(in, out);
		}
	}

	private Path artifactCacheDir(String version, String artifactId) throws IOException {
		var cacheFileDir = cacheDir().resolve(artifactId + ":" + version);
		createDirectories(cacheFileDir);
		return cacheFileDir;
	}
	
	private InputStream downloadManifest(String filename, String version, String artifactId, String groupId) {
		
		var httpClient = createHttpClient();
		var uri = URI.create(root.toString() + "/" + artifactId);
		LOG.info(format("Getting manifest from {0}", uri));
		var request = HttpRequest.newBuilder().GET().uri(uri).build();
		var handler = HttpResponse.BodyHandlers.ofInputStream();
		try {
			var response = httpClient.send(request, handler);
			switch (response.statusCode()) {
			case 200:
				return response.body();
			case 404:
				throw new NoSuchFileException(uri.toString());
			default:
				throw new IOException("Unexpected status " + response.statusCode());
			}
		} catch (InterruptedException e) {
			throw new IllegalStateException(e);
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	private HttpClient createHttpClient() {
		return HttpClient.newBuilder().build();
	}
	
	private InputStream downloadManifestAndTransformToPom(String filename, String version, String artifactId, String groupId) throws IOException {
		try (var in = getManifest(filename, version, artifactId, groupId)) {
			var object = Json.createReader(in).readObject();
			var versions = object.get("versions").asJsonObject();
			if (versions.containsKey(version)) {
				var pom = new StringBuilder();
				
				pom.append("<!-- Generated by npm2mvn - https://github.com/sshtools/npm2mvn -->\n");
				pom.append("<project xmlns=\"http://maven.apache.org/POM/4.0.0\" "
						+ "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd\">");
				pom.append("<modelVersion>4.0.0</modelVersion>\n");
				pom.append("<groupId>");
				pom.append(groupId);
				pom.append("</groupId>\n");
				pom.append("<artifactId>");
				pom.append(artifactId);
				pom.append("</artifactId>\n");
				pom.append("<version>");
				pom.append(version);
				pom.append("</version>\n");
				
				pom.append("<dependencies>");
				/* TODO */
				pom.append("</dependencies>\n");
				
				pom.append("</project>\n");
				
				return new ByteArrayInputStream(pom.toString().getBytes("UTF-8"));
			} else
				throw new NoSuchFileException(filename);
		}
	}
	
	private InputStream downloadPackageAndTransformToJar(String filename, String version, String artifactId, String groupId) throws IOException {
		try (var in = getManifest(filename, version, artifactId, groupId)) {
			var object = Json.createReader(in).readObject();
			var versions = object.get("versions").asJsonObject();
			if (versions.containsKey(version)) {
				var foundVersion = versions.get(version).asJsonObject();
				var dist = foundVersion.get("dist").asJsonObject();
				var tarball = URI.create(dist.getString("tarball"));
				
				LOG.info(format("Found @ {0}", tarball));
				
				var request = HttpRequest.newBuilder().GET().uri(tarball).build();
				var handler = HttpResponse.BodyHandlers.ofInputStream();
				try {
					var response = createHttpClient().send(request, handler);
					switch (response.statusCode()) {
					case 200:
						return tarballToJar(response.body(), filename, artifactId, groupId, version);
					case 404:
						throw new NoSuchFileException(filename);
					default:
						throw new IOException("Unexpected status " + response.statusCode());
					}
				} catch (InterruptedException e) {
					throw new IllegalStateException(e);
				}
			} else
				throw new NoSuchFileException(filename);
		}
	}
	
	private InputStream tarballToJar(InputStream body, String filename, String artifactId, String groupId, String version) throws IOException {
		var tmpDir = Files.createTempDirectory("npmx");
		var resourcePathPattern = resourcePathPattern().
				replace("%g", groupId).
				replace("%a", artifactId).
				replace("%v", version)
		;
		var crossPlatformPath = resourcePathPattern.replace("\\", "/");
		var webDir = tmpDir.resolve(resourcePathPattern.replace("/", File.separator).replace("\\", File.separator));
		
		createDirectories(webDir);
		try (var inputStream = new BufferedInputStream(body);
				var tar = new TarArchiveInputStream(new GzipCompressorInputStream(inputStream))) {
			ArchiveEntry entry;
			while ((entry = tar.getNextEntry()) != null) {
				var entryName = entry.getName();
				for(var prefix : STRIP_PREFIXES) {
					if (entryName.startsWith(prefix)) {
						var extractTo = webDir.resolve(entryName.substring(prefix.length()));
						if (entry.isDirectory()) {
							createDirectories(extractTo);
						} else {
							Files.createDirectories(extractTo.getParent());
							Files.deleteIfExists(extractTo);
							Files.copy(tar, extractTo);
						}
					}
				}
			}
		}

		/* Generate a MANIFEST.MF */
		var metaInf = tmpDir.resolve("META-INF");
		createDirectories(metaInf);
		var manifest = metaInf.resolve("MANIFEST.MF");
		var moduleName = asAutomaticModuleName(artifactId);
		try (var wrtr = new PrintWriter(Files.newOutputStream(manifest))) {
			wrtr.println("Manifest-Version: 1.0");
			wrtr.println("Automatic-Module-Name: " + moduleName);
			wrtr.println("X-NPM: " + moduleName);
			wrtr.println("X-NPM-Resources: " + crossPlatformPath);
			wrtr.println("X-NPM-GAV: " + groupId + ":" + artifactId + ":" + version);
			wrtr.println("X-NPM-Version: " + version);
		}
		
		/* Generate the locator */
		var locator = metaInf.resolve("LOCATOR." + groupId + "." + artifactId + ".properties");
		try(var out = new PrintWriter(Files.newBufferedWriter(locator))) {
			var props = new Properties();
			props.setProperty("version", version);
			props.setProperty("resource", crossPlatformPath);
			props.store(out, "Npm2Mvn");
		}
		
		/* Generate a pom.xml */
		var poms = tmpDir.resolve("META-INF").resolve("maven").resolve(groupId).resolve(artifactId);
		createDirectories(poms);
		var pomXml = poms.resolve("pom.xml");
		try(var in = getPom(filename, version, artifactId, groupId)) {
			try(var out = Files.newOutputStream(pomXml)) {
				in.transferTo(out);
			}
		}
		var pomProperties = poms.resolve("pom.properties");
		try(var out = new PrintWriter(Files.newBufferedWriter(pomProperties))) {
			var props = new Properties();
			props.setProperty("artifactId", artifactId);
			props.setProperty("groupId", groupId);
			props.setProperty("version", version);
			props.store(out, "npm2mvn");
		}

		/* Generate a layers.ini */
		var layers = tmpDir.resolve("layers.ini");
		try (var wrtr = new PrintWriter(Files.newOutputStream(layers))) {
			wrtr.println("[component]");
			wrtr.println("id = " + moduleName);
			wrtr.println();
			wrtr.println("[meta]");
			wrtr.println("source = npm");
		}

		/* Generate some native image meta-data for all resources in this package */
		var resourceDir = tmpDir.resolve("META-INF").resolve("native-image").resolve(moduleName);
		Files.createDirectories(resourceDir);
		var resourceConfig = resourceDir.resolve("resoure-config.json");
		try (var out = new PrintWriter(Files.newOutputStream(resourceConfig), true)) {
			out.println("""
						{
						"resources": {
							"includes": [
						""");
			var idx = new AtomicInteger();
			Files.walk(tmpDir).forEach(path -> {
					var rel = tmpDir.relativize(path);
				if(Files.isRegularFile(path) && !rel.startsWith("META-INF") && !rel.toString().equals("layers.ini")) {
					if(idx.getAndIncrement() > 0)
						out.println(",");
					else
						out.println();
					out.print("{ \"pattern\": \"\\\\Q" + rel + "\\\\E\" }");
				}
			});
			out.println("""
								]
							},
							"bundles": []
						}
						""");
		}

		/* Generate the jar */
		var tmpFile = Files.createTempFile("npmx", ".jar");
		tmpFile.toFile().deleteOnExit();
		try (var out = new JarOutputStream(Files.newOutputStream(tmpFile))) {
			Files.walk(tmpDir).forEach(path -> {
				try {
					if (!path.equals(tmpDir)) {
						if (!Files.isDirectory(path)) {
							var rel = tmpDir.relativize(path);
							var entry = new JarEntry(rel.toString().replace("\\", "/") + (Files.isDirectory(path) ? "/" : ""));
							entry.setTime(Files.getLastModifiedTime(path).toMillis());
							out.putNextEntry(entry);
							try (var fin = Files.newInputStream(path)) {
								fin.transferTo(out);
							}
							out.closeEntry();
						}
					}
				} catch (IOException ioe) {
					throw new UncheckedIOException(ioe);
				}
			});
		}

		return new FilterInputStream(Files.newInputStream(tmpFile)) {
			@Override
			public void close() throws IOException {
				try {
					super.close();
				} finally {
					Files.delete(tmpFile);
				}
			}
		};
	}

	private String asAutomaticModuleName(String artifactId) {
		return "npm." + artifactId.replace('-', '.').replace('_', '.');
	}
}
