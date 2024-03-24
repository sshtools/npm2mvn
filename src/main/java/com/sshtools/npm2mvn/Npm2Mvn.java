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
import java.nio.file.StandardCopyOption;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonObject;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.slf4j.bridge.SLF4JBridgeHandler;

import com.sshtools.tinytemplate.Templates.CloseableTemplateModel;
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
	
	private final static Logger LOG = Logger.getLogger(Npm2Mvn.class.getName());
	private final static int DEFAULT_HTTP_PORT = 9080;
	private final static URI root = URI.create("https://registry.npmjs.org");

	private static final Object GROUP_ID = "npm";

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
	
	@Option(names = {"-r", "--resource-path-pattern"}, description = "The pattern to use for paths of resources in generated artifacts. Default is 'npm2mvn/%%g/%%a/%%v`. %%g is replaced the group Id, %%a is replaced by the artifact Id, and %%v is replaced by the version.")
	private Optional<String> resourcePathPattern;
	
	@Option(names = {"-K", "--keystore-file"}, description = "The path to the keystore. Uses $HOME/.keystore if not specified.")
	private Optional<Path> keystoreFile;
	
	@Option(names = {"-W", "--keystore-password"}, description = "The password for the keystore. Defaults to changeit.")
	private Optional<String> keystorePassword;
	
	@Option(names = {"-k", "--key-password"}, description = "The password for the key. Defaults to changeit.")
	private Optional<String> keyPassword;
	
	@Option(names = {"-T", "--keystore-type"}, description = "The type of keystore.")
	private Optional<String> keystoreType;
	
	@Option(names = {"-R", "--no-transitive"}, description = "Do not generate <dependency> tags in poms.")
	private boolean noTransitive;
	
	private final TemplateProcessor processor;
	private final Set<String> downloading = Collections.synchronizedSet(new HashSet<>());
	
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
			LOG.info("Neither http or https specific ports supplied, falling back to http only on port " + DEFAULT_HTTP_PORT);
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
					variable("serverUrl", tx.url())));
		}
	}

	private CloseableTemplateModel findHomeTemplate() {
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
	
	private String resourcePathPattern() {
		return resourcePathPattern.orElseGet(() -> System.getProperty("resourcePathPattern", "npm2mvn/%g/%a/%v"));
	}
	
	private void handle(Transaction tx) {
		var seq = tx.match(0);
		var pathParts = seq.split("/");
		try {
			if(pathParts.length > 2) {
				var filename = pathParts[pathParts.length - 1];
				
				if(filename.startsWith("maven-metadata.xml")) {
					var groupId = String.join(".", Arrays.asList(pathParts).subList(0, pathParts.length - 2));
					if(!groupId.equals(GROUP_ID) && !groupId.startsWith(GROUP_ID + ".")) {
						throw new NoSuchFileException(seq);
					}
					
					var artifactId = pathParts[pathParts.length - 2];
					if(filename.endsWith(".xml")) {
						tx.response("text/xml", getMeta(tx, filename, groupId, artifactId));
					}
					else if(filename.endsWith(".sha1")) {
						tx.response("text/plain", getMetaDigest(tx, filename, groupId, artifactId, "SHA-1"));
					}
					else if(filename.endsWith(".md5")) {
						tx.response("text/plain", getMetaDigest(tx, filename, groupId, artifactId, "MD5"));
					}
					else if(filename.endsWith(".sha256")) {
						tx.response("text/plain", getMetaDigest(tx, filename, groupId, artifactId, "SHA-256"));
					}
					else if(filename.endsWith(".sha512")) {
						tx.response("text/plain", getMetaDigest(tx, filename, groupId, artifactId, "SHA-512"));
					}
					
				}
				else if(pathParts.length > 3) {
					var groupId = String.join(".", Arrays.asList(pathParts).subList(0, pathParts.length - 3));
					if(!groupId.equals(GROUP_ID) && !groupId.startsWith(GROUP_ID + ".")) {
						throw new NoSuchFileException(seq);
					}
					
					var version = pathParts[pathParts.length - 2];
					var artifactId = pathParts[pathParts.length - 3];
					
					if(filename.equals(artifactId + "-" + version + "-javadoc.jar")) {
						throw new NoSuchFileException(seq);
					}
					
					if(filename.equals(artifactId + "-" + version + "-sources.jar")) {
						throw new NoSuchFileException(seq);
					}
					
					if(version.endsWith("-SNAPSHOT")) {
						throw new NoSuchFileException(seq);
					}
					
					LOG.info(format("Request for {0}:{1}:{2} ({3})", groupId, artifactId, version, filename));
					
					if(filename.endsWith(".pom")) {
						tx.response("text/xml", getPom(tx, filename, version, groupId, artifactId));
					}
					else if(filename.endsWith(".jar")) {
						tx.response("application/java-archive", getJar(tx, filename, version, groupId, artifactId));
					}
					else if(filename.endsWith(".pom.sha1")) {
						tx.response("text/plain", getPomDigest(tx, filename, version, groupId, artifactId, "SHA-1"));
					}
					else if(filename.endsWith(".pom.md5")) {
						tx.response("text/plain", getPomDigest(tx, filename, version, groupId, artifactId, "MD5"));
					}
					else if(filename.endsWith(".pom.sha256")) {
						tx.response("text/plain", getPomDigest(tx, filename, version, groupId, artifactId, "SHA-256"));
					}
					else if(filename.endsWith(".pom.sha512")) {
						tx.response("text/plain", getPomDigest(tx, filename, version, groupId, artifactId, "SHA-512"));
					}
					else if(filename.endsWith(".jar.sha1")) {
						tx.response("text/plain", getJarDigest(tx, filename, version, groupId, artifactId, "SHA-1"));
					}
					else if(filename.endsWith(".jar.md5")) {
						tx.response("text/plain", getJarDigest(tx, filename, version, groupId, artifactId, "MD5"));
					}
					else if(filename.endsWith(".jar.sha256")) {
						tx.response("text/plain", getJarDigest(tx, filename, version, groupId, artifactId, "SHA-256"));
					}
					else if(filename.endsWith(".jar.sha512")) {
						tx.response("text/plain", getJarDigest(tx, filename, version, groupId, artifactId, "SHA-512"));
					}
					else
						throw new NoSuchFileException(seq);
				}
				else
					throw new NoSuchFileException(seq);
			}
		}
		catch(NoSuchFileException nsfe) {
			if(LOG.isLoggable(Level.FINE))
				LOG.fine(format("Not found. {0}", nsfe.getFile()));
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
	
	private InputStream getMetaDigest(Transaction tx, String filename, String groupId, String artifactId, String algo) throws IOException, NoSuchAlgorithmException {
		var cacheFileDir = artifactCacheDir(null, groupId, artifactId);
		var cacheFile = cacheFileDir.resolve(groupId + ":" + artifactId + ".maven-metadata." + algoExtension(algo));
		if(Files.exists(cacheFile)) {
			LOG.info(format("Responding with meta {0} from the cache @ {1}", algo, cacheFile));
		}
		else {
			var digest = MessageDigest.getInstance(algo);
			try(var digestIn = new DigestInputStream(getMeta(tx, filename, groupId, artifactId), digest)) {
				digestIn.transferTo(OutputStream.nullOutputStream());
				try(var wtr = Files.newBufferedWriter(cacheFile)) {
					wtr.write(Hex.encodeHexString(digest.digest()));
					wtr.newLine();
				}
			};
		}
		return Files.newInputStream(cacheFile);
	}
	
	private InputStream getPomDigest(Transaction tx, String filename, String version, String groupId, String artifactId, String algo) throws IOException, NoSuchAlgorithmException {
		var cacheFileDir = artifactCacheDir(version, groupId, artifactId);
		var cacheFile = cacheFileDir.resolve(groupId + ":" + artifactId + ":" + version + ".pom." + algoExtension(algo));
		if(Files.exists(cacheFile)) {
			LOG.info(format("Responding with POM {0} from the cache @ {2}", algo, cacheFile));
		}
		else {
			var digest = MessageDigest.getInstance(algo);
			try(var digestIn = new DigestInputStream(getPom(tx, filename, version, groupId, artifactId), digest)) {
				digestIn.transferTo(OutputStream.nullOutputStream());
				try(var wtr = Files.newBufferedWriter(cacheFile)) {
					wtr.write(Hex.encodeHexString(digest.digest()));
					wtr.newLine();
				}
			};
		}
		return Files.newInputStream(cacheFile);
	}
	
	private InputStream getJarDigest(Transaction tx, String filename, String version, String groupId, String artifactId, String algo) throws IOException, NoSuchAlgorithmException {
		var cacheFileDir = artifactCacheDir(version, groupId, artifactId);
		var cacheFile = cacheFileDir.resolve(groupId + ":" + artifactId + ":" + version + "." + algoExtension(algo));
		if(Files.exists(cacheFile)) {
			LOG.info(format("Responding with Jar {0} from the cache @ {1}", cacheFile, algo));
		}
		else {
			var digest = MessageDigest.getInstance(algo);
			try(var digestIn = new DigestInputStream(getJar(tx, filename, version, groupId, artifactId), digest)) {
				digestIn.transferTo(OutputStream.nullOutputStream());
				try(var wtr = Files.newBufferedWriter(cacheFile)) {
					wtr.write(Hex.encodeHexString(digest.digest()));
					wtr.newLine();
				}
			};
		}
		return Files.newInputStream(cacheFile);
	}

	private String algoExtension(String algo) {
		return algo.toLowerCase().replace("-", "");
	}
	
	private InputStream getMeta(Transaction tx, String filename, String groupId, String artifactId) throws IOException {
		var cacheFileDir = artifactCacheDir(null, groupId, artifactId);
		var cacheFile = cacheFileDir.resolve(groupId + ":" + artifactId + ".maven-metadata.xml");
		if(Files.exists(cacheFile)) {
			LOG.info(format("Responding with metadata {0} from the cache @ {1}", artifactId, cacheFile));
			return Files.newInputStream(cacheFile);
		}
		else {
			var in = downloadManifestAndTransformToMeta(tx, filename, groupId, artifactId);
			LOG.info(format("Responding with fresh copy of metadata {0} from NPM", artifactId));
			var out = Files.newOutputStream(cacheFile);
			return new TeeInputStream(in, out);
		}
	}
	
	private InputStream getPom(Transaction tx, String filename, String version, String groupId, String artifactId) throws IOException {
		var cacheFileDir = artifactCacheDir(version, groupId, artifactId);
		var cacheFile = cacheFileDir.resolve(groupId + ":" + artifactId + ":" + version + ".pom");
		if(Files.exists(cacheFile)) {
			LOG.info(format("Responding with POM {0} from the cache @ {1}", artifactId, cacheFile));
			return Files.newInputStream(cacheFile);
		}
		else {
			var in = downloadManifestAndTransformToPom(tx, filename, version, groupId, artifactId);
			LOG.info(format("Responding with fresh copy of POM {0} from NPM", artifactId));
			var out = Files.newOutputStream(cacheFile);
			return new TeeInputStream(in, out);
		}
	}
	
	private InputStream getJar(Transaction tx, String filename, String version, String groupId, String artifactId) throws IOException {
		var cacheFileDir = artifactCacheDir(version, groupId, artifactId);
		var cacheFile = cacheFileDir.resolve(groupId + ":" + artifactId + ":" + version + ".jar");
		if(Files.exists(cacheFile)) {
			LOG.info(format("Responding with Jar {0} from the cache @ {1}", artifactId, cacheFile));
			return Files.newInputStream(cacheFile);
		}
		else {
			var in = downloadPackageAndTransformToJar(tx, filename, version, groupId, artifactId);
			LOG.info(format("Responding with fresh copy of transform Jar {0} from NPM", artifactId));
			var out = Files.newOutputStream(cacheFile);
			return new TeeInputStream(in, out);
		}
	}
	
	private InputStream getManifest(String filename, String groupId, String artifactId) throws IOException {
		var cacheFileDir = artifactCacheDir(null, groupId, artifactId);
		var cacheFile = cacheFileDir.resolve(groupId + ":" + artifactId + ".json");
		if(Files.exists(cacheFile)) {
			LOG.info(format("Responding with manifest {0} from the cache @ {1}", artifactId, cacheFile));
			return Files.newInputStream(cacheFile);
		}
		else {
			var in = downloadManifest(filename, groupId, artifactId);
			LOG.info(format("Responding with fresh copy manifest of {0} from NPM", artifactId));
			var out = Files.newOutputStream(cacheFile);
			return new TeeInputStream(in, out);
		}
	}

	private Path artifactCacheDir(String version, String groupId, String artifactId) throws IOException {
		var cacheFileDir = cacheDir().resolve(groupId + ":" + artifactId + (version == null ? "" : ":" + version));
		createDirectories(cacheFileDir);
		return cacheFileDir;
	}
	
	private InputStream downloadManifest(String filename, String groupId, String artifactId) {
		
		var httpClient = createHttpClient();
		var uri = groupId.equals(GROUP_ID) ? 
				URI.create(root.toString() + "/" + artifactId) : 
				URI.create(root.toString() + "/@" + groupId.substring(4) + "/" + artifactId);
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

	
	private InputStream downloadManifestAndTransformToMeta(Transaction tx, String filename, String groupId, String artifactId) throws IOException {
		try (var in = getManifest(filename, groupId, artifactId)) {
			var object = Json.createReader(in).readObject();
			var versions = object.get("versions").asJsonObject();
			var meta = new StringBuilder();
			var versionNumbers = new ArrayList<>(versions.keySet());
			
			var current = versionNumbers.get(versionNumbers.size() - 1);
			var release = current;
			
			if(object.containsKey("dist-tags")) {
				var distTags = object.get("dist-tags").asJsonObject();
				if(distTags.containsKey("latest")) {
					release = distTags.getString("latest");
				}
			}
			
			meta.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
			meta.append("<metadata>\n");
			meta.append("  <groupId>");
			meta.append(groupId);
			meta.append("</groupId>\n");
			meta.append("  <artifactId>");
			meta.append(artifactId);
			meta.append("</artifactId>\n");
			meta.append("    <versioning>\n");
			meta.append("      <latest>");
			meta.append(current);
			meta.append("</latest>\n");
			meta.append("      <release>");
			meta.append(release);
			meta.append("</release>\n");
			meta.append("      <versions>\n");
			versionNumbers.forEach(v -> {
				meta.append("        <version>");
				meta.append(v);
				meta.append("</version>\n");
				
			});
			meta.append("</versions>\n");

			meta.append("      <lastUpdated>");
			meta.append(new SimpleDateFormat("yyyyMMddHHmmss").format(new Date()));
			meta.append("</lastUpdated>");
			meta.append("  </versioning>\n");
			meta.append("</metadata>\n");
			return new ByteArrayInputStream(meta.toString().getBytes("UTF-8"));
		}
	}
	
	private InputStream downloadManifestAndTransformToPom(Transaction tx, String filename, String version, String groupId, String artifactId) throws IOException {
		try (var in = getManifest(filename, groupId, artifactId)) {
			var object = Json.createReader(in).readObject();
			var versions = object.get("versions").asJsonObject();
			if (versions.containsKey(version)) {
				var pom = new StringBuilder();
				
				// https://maven.apache.org/pom.html
				
				pom.append("<!-- Generated by npm2mvn - https://github.com/sshtools/npm2mvn -->\n");
				pom.append("<project xmlns=\"http://maven.apache.org/POM/4.0.0\" "
						+ "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd\">");
				pom.append("<modelVersion>4.0.0</modelVersion>\n");
				pom.append("<packaging>jar</packaging>");
				pom.append("<groupId>");
				pom.append(groupId);
				pom.append("</groupId>\n");
				pom.append("<artifactId>");
				pom.append(artifactId);
				pom.append("</artifactId>\n");
				pom.append("<version>");
				pom.append(version);
				pom.append("</version>\n");
				
				var versionObj = versions.get(version).asJsonObject();
				
				/* Other metadata
				 * 
				 * https://docs.npmjs.com/cli/v6/configuring-npm/package-json
				 * */ 
				addTagFromProperty(pom, versionObj, "name", "name");
				addTagFromProperty(pom, versionObj, "description", "description");
				addTagFromProperty(pom, versionObj, "homepage", "url");
				
				try {
					var desc = versionObj.getString("license");
					pom.append("<licenses><license><name>");
					pom.append(encodeXml(desc));
					pom.append("</name></license></licenses>\n");
				}
				catch(Exception e) {}
				
				try {
					var desc = versionObj.getJsonObject("author");
					pom.append("<developers><developer>");
					addTagFromProperty(pom, desc, "name", "id");
					addTagFromProperty(pom, desc, "name", "name");
					addTagFromProperty(pom, desc, "email", "email");
					addTagFromProperty(pom, desc, "url", "url");
					pom.append("</developer></developers>\n");
				}
				catch(Exception e) {}
				
				try {
					var desc = versionObj.getJsonObject("bugs");
					pom.append("<issueManagement>");
					addTagFromProperty(pom, desc, "url", "url");
					pom.append("</issueManagement>\n");
				}
				catch(Exception e) {}
				
				
				/* 
				 * Deps 
				 * https://stackoverflow.com/questions/18875674/whats-the-difference-between-dependencies-devdependencies-and-peerdependencie
				 * 
				 * */
				
				if(!noTransitive) {
					var distTags = new HashMap<String, String>();
					if(object.containsKey("dist-tags")) {
						var ts = object.get("dist-tags").asJsonObject();
						for(var k : ts.keySet()) {
							distTags.put(k, ts.getString(k));
						}
						
					}
					
					JsonObject deps = null, peerDeps = null, optDeps = null, peerDepsMeta = null;
					try { deps = versionObj.getJsonObject("dependencies"); } catch(Exception e) {}
					try { optDeps = versionObj.getJsonObject("optionalDependencies"); } catch(Exception e) {}
//					try { peerDeps = versionObj.getJsonObject("peerDependencies"); } catch(Exception e) {}
//					try { peerDepsMeta = versionObj.getJsonObject("peerDependenciesMeta"); } catch(Exception e) {}
					
					if(deps != null || optDeps != null || peerDeps != null) {
						var done = new HashSet<String>();
						pom.append("<dependencies>");
						addDeps(pom, deps, null, distTags, done, null);
//						addDeps(pom, peerDeps, peerDepsMeta, distTags, done);
						addDeps(pom, optDeps, null, distTags, done, true);
						pom.append("</dependencies>\n");
	//					pom.append("<repositories>");
	//					
	//					/* TODO IMPORTANT,INSECURE! anyone could use their own hostname and cache that 
	//					 * for others to retrieve, potentially downloading dependencies from
	//					 * an untrusted source.
	//					 * 
	//					 * We need fixed configuration for this.
	//					 */
	//					pom.append("<repository>");
	//					pom.append("<id>npm2mvn</id>");
	//					pom.append("<url>");
	//					if(tx.secure())
	//						pom.append("https://" + tx.host());
	//					else
	//						pom.append("http://" + tx.host());
	//					pom.append("</url>");
	//					pom.append("</repository>\n"); 
	//					
	//					pom.append("</repositories>\n");
					}
				}
				
				pom.append("</project>\n");
				
				return new ByteArrayInputStream(pom.toString().getBytes("UTF-8"));
			} else
				throw new NoSuchFileException(filename);
		}
	}

	private void addDeps(StringBuilder pom, JsonObject deps, JsonObject meta, Map<String, String> distTags, HashSet<String> done, Boolean opt) {
		if(deps == null)
			return;
		for(var dep : deps.keySet()) {
			if(done.contains(dep)) {
				continue;
			}
			done.add(dep);
			var ver = deps.getString(dep);
			pom.append("<dependency>");
			var artId = dep;							
				pom.append("<groupId>");
			if(dep.startsWith("@")) {							
				var parts = dep.substring(1).split("/");
				pom.append("npm.");
				pom.append(parts[0]);
				artId = parts[1];
			}
			else {
				pom.append(GROUP_ID);
			}
			pom.append("</groupId>");
			pom.append("<artifactId>");
			pom.append(artId);
			pom.append("</artifactId>");
			pom.append("<version>");
			pom.append(translateVersion(distTags, ver));
			pom.append("</version>");
			if(meta != null) {
				try {
					var obj = meta.getJsonObject(dep);
					if(obj.containsKey("optional")) {
						opt = obj.getBoolean("optional");
					}
				}
				catch(Exception e) {
				}
			}
			if(opt != null) {
				pom.append("<optional>");
				pom.append(opt);
				pom.append("</optional>");
			}
			pom.append("</dependency>\n");
			
		}
	}

	private String translateVersion(Map<String, String> distTags, String ver) {
		
		ver = ver.trim();
		
		var b = new StringBuilder();
		if(ver.equals("*")) {
			b.append("LATEST");
		}
		else if(ver.equals("")) {
			b.append("RELEASE");
		}
		else {
			var vers = ver.split("\\|\\|");
			for(var v : vers) {
				var firstVer = b.length() == 0; 
				if(!firstVer) { 
					b.append(",");
				}
				
				v = v.trim();
				
				try {
					var num = Integer.parseInt(v);
					v = ">=" + num + " <" + ( num + 1);
				}
				catch(Exception e) {
				}
				
				var f = v.split("\\s+");
				var first = f[0].trim();
				
				if(f.length> 2 && f[1].equals("-")) {
					f[0] = ">=" + f[0];
					f[2] = "<=" + f[2];
					f = new String[] { f[0], f[2] };
				}
				
				if(first.startsWith(">=")) {
					b.append("[");
					b.append(first.substring(2));
					b.append(",");
					if(f.length > 1) {
						var second = f[1];
						if(second.startsWith("<=")) {
							b.append(second.substring(2));
							b.append("]");
						}
						else if(second.startsWith("<")) {
							b.append(second.substring(1));
							b.append(")");
						}
						else {
							b.append(")");
						}
					}
					else {
						b.append(")");
					}
					 
				}
				else if(first.startsWith(">")) {
					b.append("(");
					b.append(first.substring(1));
					b.append(",");
					if(f.length > 1) {
						var second = f[1];
						if(second.startsWith("<=")) {
							b.append(second.substring(2));
							b.append("]");
						}
						else if(second.startsWith("<")) {
							b.append(second.substring(1));
							b.append(")");
						}
						else {
							b.append(")");
						}
					}
					else {
						b.append(")");
					}
				}
				else if(first.startsWith("<=")) {
					if(f.length > 1) {
						var second = f[1];
						if(second.startsWith("<=")) {
							b.append("[");
							b.append(second.substring(2));
						}
						else if(second.startsWith("<")) {
							b.append("(");
							b.append(second.substring(1));
						}
						else {
							b.append("[");
						}
					}
					else {
						b.append("[");
					}
					b.append(",");
					b.append(first.substring(2));
					b.append(")");
				}
				else if(first.startsWith("<")) {
					if(f.length > 1) {
						var second = f[1];
						if(second.startsWith("<=")) {
							b.append("[");
							b.append(second.substring(2));
						}
						else if(second.startsWith("<")) {
							b.append("(");
							b.append(second.substring(1));
						}
						else {
							b.append("(");
						}
					}
					else {
						b.append("(");
					}
					b.append(",");
					b.append(first.substring(1));
					b.append(")");
				}
				else if(first.startsWith("~") || first.startsWith("^")) {
					/* TODO not quite right, but not sure what else to do here. */
					if(firstVer && vers.length == 1)
						b.append(first.substring(1));
					else
						b.append("[" + first.substring(1) + "]");
					break;
				}
				else if(first.matches("[a-zA-Z]+.*")) {
					if(distTags.containsKey(first)) {
						b.append(distTags.get(first));	
					}
					else {
						b.append("RELEASE");
					}
					break;
				}
				else {
					if(first.contains(".x")) {
						first = "[" + first.replace(".x", "") + ",)";
					}
					else {
						try {
							var vv = Integer.parseInt(first);
							b.append("[" + vv + "," + (vv + 1) + ")");
						}
						catch(Exception e) {
							b.append("[" + first + "]");
						}
					}
					break;
				}
				
			}
		}
		
		return b.toString();
	}

	private void addTagFromProperty(StringBuilder pom, JsonObject versionObj, String key, String tag) {
		try {
			var desc = versionObj.getString(key);
			pom.append("<" + tag + ">");
			pom.append(encodeXml(desc));
			pom.append("</" + tag + ">\n");
		}
		catch(Exception e) {}
	}
	
	private static String encodeXml(String s) {
		StringBuilder sb = new StringBuilder();
		int len = s.length();
		for (int i = 0; i < len;) {
			int c = s.codePointAt(i);
			if (c < 0x80) {
				if (c < 0x20 && (c != '\t' && c != '\r' && c != '\n')) {
					sb.append("&#xfffd;");
				} else {
					switch (c) {
					case '&':
						sb.append("&amp;");
						break;
					case '>':
						sb.append("&gt;");
						break;
					case '<':
						sb.append("&lt;");
						break;
//                  case '\"'  sb.append("&quot;"); break;
//                  case '\n'  sb.append("&#10;"); break;
//                  case '\r'  sb.append("&#13;"); break;
//                  case '\t'  sb.append("&#9;"); break;
					default:
						sb.append((char) c);
					}
				}
			} else if ((c >= 0xd800 && c <= 0xdfff) || c == 0xfffe || c == 0xffff) {
				sb.append("&#xfffd;");
			} else {
				sb.append("&#x");
				sb.append(Integer.toHexString(c));
				sb.append(';');
			}
			i += c <= 0xffff ? 1 : 2;
		}
		return sb.toString();
	}
	
	private InputStream downloadPackageAndTransformToJar(Transaction tx, String filename, String version, String groupId, String artifactId) throws IOException {
		try (var in = getManifest(filename, groupId, artifactId)) {
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
						return tarballToJar(tx, response.body(), filename, groupId, artifactId, version, foundVersion);
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
	
	private InputStream tarballToJar(Transaction tx, InputStream body, String filename, String groupId, String artifactId, String version, JsonObject versionManifest) throws IOException {
		var tmpDir = Files.createTempDirectory("npmx");
		var resourcePathPattern = resourcePathPattern().
				replace("%g", groupId).
				replace("%a", artifactId).
				replace("%v", version)
		;
		var crossPlatformPath = resourcePathPattern.replace("\\", "/");
		var webDir = tmpDir.resolve(resourcePathPattern.replace("/", File.separator).replace("\\", File.separator));
		
		/* 
		 * There is no standard layout for a package. `dist` is *usually* where minified or
		 * otherwise processed files intended for distribution, but this is not always the
		 * case.
		 * 
		 * For this reason, we just mirror the same layout. It is up to the developer adding
		 * the dependency where to load resources from. 
		 * 
		 * The `main`, `sass`, `style` attributes would often point to dist and should be
		 * used when available.
		 * 
		 * Ref. https://stackoverflow.com/questions/39729194/role-of-the-src-and-dist-folders-in-npm-packages
		 */
		createDirectories(webDir);
		try (var inputStream = new BufferedInputStream(body);
				var tar = new TarArchiveInputStream(new GzipCompressorInputStream(inputStream))) {
			ArchiveEntry entry;
			while ((entry = tar.getNextEntry()) != null) {
				var entryName = entry.getName();
					if (entryName.startsWith("package/")) {
						var extractTo = webDir.resolve(entryName.substring(8));
						if (entry.isDirectory()) {
							createDirectories(extractTo);
						} else {
							Files.createDirectories(extractTo.getParent());
							Files.deleteIfExists(extractTo);
							Files.copy(tar, extractTo, StandardCopyOption.REPLACE_EXISTING);
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
		
		/* Copy the npm manifest to META-INF too */
		var packages = metaInf.resolve("PACKAGES." + groupId + "." + artifactId + ".json");
		try(var in = getManifest(filename, groupId, artifactId)) {
			try(var out = Files.newOutputStream(packages)) {
				in.transferTo(out);
			}		
		}		
		
		/* Generate the locator */
		var locator = metaInf.resolve("LOCATOR." + groupId + "." + artifactId + ".properties");
		try(var out = new PrintWriter(Files.newBufferedWriter(locator))) {
			var props = new Properties();
			props.setProperty("version", version);
			props.setProperty("resource", crossPlatformPath);
			addPropertyFromElement(versionManifest, "type", props); 
			addPropertyFromElement(versionManifest, "sass", props); 
			addPropertyFromElement(versionManifest, "main", props); 
			addPropertyFromElement(versionManifest, "module", props); 
			addPropertyFromElement(versionManifest, "style", props);  
			props.store(out, "Npm2Mvn");
		}	
		
		/* Generate the file catalogue */
		var catalogue = metaInf.resolve("CATALOGUE." + groupId + "." + artifactId + ".list");
		try(var out = new PrintWriter(Files.newBufferedWriter(catalogue))) {
			Files.walk(webDir).forEach(path -> {
				var rel = webDir.relativize(path).toString().replace('\\', '/');
				if(Files.isRegularFile(path)) {
					out.println(rel);
				}
			});
		}
		
		/* Generate a pom.xml */
		var poms = tmpDir.resolve("META-INF").resolve("maven").resolve(groupId).resolve(artifactId);
		createDirectories(poms);
		var pomXml = poms.resolve("pom.xml");
		try(var in = getPom(tx, filename, version, groupId, artifactId)) {
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

		/* Generate some native image meta-data for all resources in this package */
		var resourceDir = tmpDir.resolve("META-INF").resolve("native-image").resolve(moduleName);
		Files.createDirectories(resourceDir);
		var resourceConfig = resourceDir.resolve("resource-config.json");
		try (var out = new PrintWriter(Files.newOutputStream(resourceConfig), true)) {
			out.println("""
						{
						"resources": {
							"includes": [
						""");
			var idx = new AtomicInteger();
			Files.walk(tmpDir).forEach(path -> {
				var rel = tmpDir.relativize(path).toString().replace('\\', '/');
				if(Files.isRegularFile(path) && !rel.startsWith("META-INF/native-image") && !rel.equals("layers.ini")) {
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

	private void addPropertyFromElement(JsonObject json, String key, Properties props) {
		if(json.containsKey(key))
			props.setProperty(key, json.getString(key));
	}

	private String asAutomaticModuleName(String artifactId) {
		return "npm." + artifactId.replace('-', '.').replace('_', '.');
	}
}
