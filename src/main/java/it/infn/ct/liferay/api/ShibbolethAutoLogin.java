package it.infn.ct.liferay.api;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

import com.liferay.portal.kernel.exception.NoSuchUserException;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.model.User;
import com.liferay.portal.kernel.security.auto.login.AutoLogin;
import com.liferay.portal.kernel.security.auto.login.AutoLoginException;
import com.liferay.portal.kernel.security.auto.login.BaseAutoLogin;
import com.liferay.portal.kernel.service.UserLocalService;
import com.liferay.portal.kernel.util.PortalUtil;
import com.liferay.portal.kernel.util.StackTraceUtil;
import com.liferay.portal.kernel.util.Validator;

@Component(immediate = true, service = AutoLogin.class)
public class ShibbolethAutoLogin extends BaseAutoLogin {
	private static Log log = LogFactoryUtil.getLog(ShibbolethAutoLogin.class);

	@Override
	public String[] doLogin(HttpServletRequest request, HttpServletResponse response) throws AutoLoginException {

		String[] credentials = null;
		Pattern pat = Pattern.compile("[\\w\\-]([\\.\\w\\-])+@([\\w\\-]+\\.)+[a-zA-Z]{2,4}");
		Matcher mailMatch;

		long companyId = 0;

		try {
			companyId = PortalUtil.getCompany(request).getCompanyId();

			if (request.getAttribute("mail") != null) {
				mailMatch = pat.matcher((String) request.getAttribute("mail"));
				while (mailMatch.find()) {
					try {
						if (Validator.isNotNull(mailMatch.group())) {

							User user = _userLocalService.getUserByEmailAddress(companyId, mailMatch.group());
							credentials = new String[3];

							log.error("Checked user by mail: " + user.getScreenName());
							// log.error(user.getUserId()+" is not an
							// Omniadmin!");
							credentials[0] = String.valueOf(user.getUserId());
							credentials[1] = user.getPassword();
							credentials[2] = Boolean.TRUE.toString();
							return credentials;
						}
					} catch (NoSuchUserException e) {
						log.info("Mail: " + mailMatch.group() + " is not registered");
						// throw new AutoLoginException(e.getMessage());

					}
				}

				if (credentials == null)
					throw new AutoLoginException("No user's mails registered");
			}
		} catch (Exception e) {
			log.error(StackTraceUtil.getStackTrace(e));
			throw new AutoLoginException(e);
		}
		return null;
	}
	@Reference(unbind = "-")
	protected void setUserLocalService(UserLocalService userLocalService) {
		_userLocalService = userLocalService;
	}

	private UserLocalService _userLocalService;

}