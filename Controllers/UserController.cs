using AccountManagementSecurity.Areas.Identity.Pages.Account;
using AccountManagementSecurity.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AccountManagementSecurity.Controllers
{
    [Authorize(Roles = "Admin,Mediator")]
    [AutoValidateAntiforgeryToken]
    public class UserController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<UserController> _logger;

        public UserController(UserManager<ApplicationUser> userManager, ILogger<UserController> logger)
        {
            _userManager = userManager;
            _logger = logger;
        }

        // GET: UserController
        public async Task<ActionResult> ListUsers()
        {
            IEnumerable<ApplicationUser> users = _userManager.Users;

            if (User.HasClaim(ClaimTypes.Role, "Mediator"))
                users = await _userManager.GetUsersForClaimAsync(new Claim(ClaimTypes.Role, "Speler"));

            users = users.Where(u => u.Id != User.FindFirstValue(ClaimTypes.NameIdentifier)); // Do not include logged in user
            return View(users);
        }

        // GET: UserController/Details/5
        public async Task<ActionResult> Details(string id)
        {
            var user = await _userManager.FindByIdAsync(id);

            if (user == null)
                return NotFound("Something went wrong. If this issue persists, contact support with error code 53");

            List<SelectListItem> roles = new List<SelectListItem>
            {
                new SelectListItem { Value = "Speler", Text = "Speler" },
                new SelectListItem { Value = "Mediator", Text = "Mediator"},
                new SelectListItem { Value = "Admin", Text = "Admin" },
            };
            ViewBag.roles = roles;

            var model = new ApplicationUser()
            {
                Id = user.Id,
                UserName = user.UserName,
                Email = user.Email,
                PhoneNumber = user.PhoneNumber,
                GamesWon = user.GamesWon,
                GamesLost = user.GamesLost
            };

            return View(model);
        }

        // GET: UserController/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: UserController/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin")]
        public async Task<ActionResult> Create([Bind("UserName, Email, Password, ConfirmPassword")] RegisterModel.InputModel input)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = input.Email, Email = input.Email };
                await _userManager.CreateAsync(user, input.Password);
                return RedirectToAction(nameof(Details), user);
            }

            return RedirectToAction(nameof(ListUsers));
        }

        // GET: UserController/Edit/5
        public async Task<ActionResult> Edit(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound("deze bestaat niet");
            }
            var model = new EditInputModel()
            { Id = user.Id, UserName = user.UserName, Email = user.Email, PhoneNumber = user.PhoneNumber };
            return View(model);
        }

        // POST: UserController/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin")]
        public async Task<ActionResult> EditUserName([Bind("Id, UserName")] EditInputModel input)
        {
            var user = await _userManager.FindByIdAsync(input.Id);
            if (user == null)
                return NotFound($"Unable to load user.");

            if (ModelState.IsValid)
            {
                if (user.UserName != input.UserName)
                {
                    user.UserName = input.UserName;
                    await _userManager.UpdateAsync(user);
                    return RedirectToAction(nameof(Details), user);
                }
            }

            return RedirectToAction(nameof(Edit), user);
        }

        // POST: UserController/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Policy = "MultiFactorAuthentication")]
        public async Task<ActionResult> EditEmail([Bind("Id, Email")] EditInputModel input)
        {
            var user = await _userManager.FindByIdAsync(input.Id);
            if (user == null)
                return NotFound($"Unable to load user.");

            if (ModelState.IsValid)
            {
                if (user.Email != input.Email)
                {
                    user.Email = input.Email;
                    await _userManager.UpdateAsync(user);

                    return RedirectToAction(nameof(Details), user);
                }
            }

            return RedirectToAction(nameof(Edit), user);
        }

        // POST: UserController/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin")]
        public async Task<ActionResult> EditPhoneNumber([Bind("Id, PhoneNumber")] EditInputModel input)
        {
            var user = await _userManager.FindByIdAsync(input.Id);
            if (user == null)
                return NotFound($"Unable to load user.");

            if (ModelState.IsValid)
            {
                if (user.PhoneNumber != input.PhoneNumber)
                {
                    user.PhoneNumber = input.PhoneNumber;
                    await _userManager.UpdateAsync(user);
                    return RedirectToAction(nameof(Details), user);
                }
            }

            return RedirectToAction(nameof(Edit), user);
        }

        // POST: UserController/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin")]
        public async Task<ActionResult> EditPassword([Bind("Id, Password")] EditInputModel input)
        {
            var user = await _userManager.FindByIdAsync(input.Id);
            if (user == null)
                return NotFound($"Unable to load user.");

            if (ModelState.IsValid)
            {
                // om dit werkend te krijgen moet voor de user in de database EmailConfirmed de waarde 'true' hebben
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                await _userManager.ResetPasswordAsync(user, token, input.Password);

                return RedirectToAction(nameof(Details), user);
            }

            return RedirectToAction(nameof(Edit), user);
        }

        // POST: UserController/Ban/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Policy = "MultiFactorAuthentication")]
        public async Task<ActionResult> Ban([Bind("Id")] ApplicationUser input)
        {
            double timeBannedInMinutes = 1;
            var user = await _userManager.FindByIdAsync(input.Id);

            await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.Now + TimeSpan.FromMinutes(timeBannedInMinutes));

            return RedirectToAction(nameof(ListUsers));
        }

        // POST: UserController/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin")]
        public async Task<ActionResult> Delete([Bind("Id")] ApplicationUser input)
        {
            var user = await _userManager.FindByIdAsync(input.Id);

            await _userManager.DeleteAsync(user);

            return RedirectToAction(nameof(ListUsers));
        }

        // POST: UserController/AddRole/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin")]
        public async Task<ActionResult> AddRole([Bind("Id, UserName")] ApplicationUser input)
        {
            var user = await _userManager.FindByIdAsync(input.Id);
            var claims = await _userManager.GetClaimsAsync(user);

            await _userManager.RemoveClaimsAsync(user, claims);
            await _userManager.AddClaimAsync(user, new Claim(ClaimTypes.Role, input.UserName));
            if (input.UserName == "Admin" || input.UserName == "Mediator")
            {
                user.LockoutEnabled = false;
                await _userManager.AddClaimAsync(user, new Claim("mfa", "mfa"));
            }

            return RedirectToAction(nameof(ListUsers));
        }
    }
}
