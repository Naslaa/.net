using _12.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Security.Claims;
namespace AuthorizeAuthenticate.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }
        public IActionResult Index()
        {
            return View();
        }
        public IActionResult Privacy()
        {
            return View();
        }
        [Authorize]
        public IActionResult Secured()
        {
            return View();
        }
        [Authorize(Roles = "Admin")]
        public IActionResult Secret()
        {
            return View();
        }
        [HttpGet]
        public IActionResult login(string ReturnUrl)
        {
            ViewData["returnedUrl"] = ReturnUrl;
            return View();
        }
        [HttpPost("Home/login")]
        public IActionResult Verify(string username, string password, string ReturnUrl)
        {
            if (ValidateCredentials(username, password))
            {
                var claims = new List<Claim>
{
new Claim(ClaimTypes.NameIdentifier, username),
new Claim(ClaimTypes.Name, username)
};
                if (username == "Nasla")
                {
                    claims.Add(new Claim(ClaimTypes.Role, "Admin"));
                }
                var claimsIdentity = new ClaimsIdentity(claims,
                CookieAuthenticationDefaults.AuthenticationScheme);
                var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
                HttpContext.SignInAsync(claimsPrincipal);
                return Redirect(ReturnUrl);
            }
            return BadRequest();
        }
        private bool ValidateCredentials(string username, string password)
        {
            return (username == "Nasla" && password == "Nasla") ||
            (username == "Nasla" && password == "Nasla");
        }
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel
            {
                RequestId = Activity.Current?.Id ??
            HttpContext.TraceIdentifier
            });
        }
    }
}