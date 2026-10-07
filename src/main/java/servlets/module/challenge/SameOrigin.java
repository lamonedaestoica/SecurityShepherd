package servlets.module.challenge;

import java.net.URI;
import javax.servlet.http.HttpServletRequest;

/**
 * Origin check for state-changing requests, as the OWASP CSRF cheat sheet describes it: the Origin
 * header (or, failing that, the Referer) must name this host. A request carrying neither is refused
 * - for an action that changes another user's state, "no evidence of where it came from" cannot
 * count as "came from this application".
 */
final class SameOrigin {

  private SameOrigin() {}

  static boolean check(HttpServletRequest request) {
    String host = request.getHeader("Host");
    if (host == null) {
      return false;
    }
    String source = request.getHeader("Origin");
    if (source == null || source.trim().isEmpty() || "null".equals(source)) {
      source = request.getHeader("Referer");
    }
    if (source == null || source.trim().isEmpty()) {
      return false;
    }
    try {
      String authority = URI.create(source).getRawAuthority();
      return authority != null && authority.equalsIgnoreCase(host);
    } catch (IllegalArgumentException e) {
      return false;
    }
  }
}
