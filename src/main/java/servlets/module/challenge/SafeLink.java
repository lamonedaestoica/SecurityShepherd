package servlets.module.challenge;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Validation for links built from user input. A value is used as a link only if it parses as an
 * absolute http or https URL with a host; anything else - a quote that breaks out of the href, a
 * javascript: URL, a stray event handler - is replaced by a fixed, harmless link. Callers still
 * encode the result for the attribute or text it is written into.
 */
final class SafeLink {

  static final String DEFAULT = "https://www.owasp.org/index.php/OWASP_Security_Shepherd";

  private SafeLink() {}

  static String of(String candidate) {
    if (candidate == null) {
      return DEFAULT;
    }
    try {
      URI uri = new URI(candidate.trim());
      String scheme = uri.getScheme();
      if (scheme != null
          && (scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))
          && uri.getHost() != null) {
        return uri.toString();
      }
    } catch (URISyntaxException e) {
      // falls through to the default
    }
    return DEFAULT;
  }
}
