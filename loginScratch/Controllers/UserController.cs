using loginScratch.Models;
using SimpleCrypto;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace loginScratch.Controllers
{
    public class UserController : Controller
    {
        //
        // GET: /User/

        public ActionResult Index()
        {
            return View();
        }
        [HttpGet]
        public ActionResult Login()
        {
            return View();
        }
        [HttpPost]
        public ActionResult Login(log_in user)
        {
            
            if (ValidPass(user.email, user.pass))
            {
                FormsAuthentication.SetAuthCookie(user.email, false);
                return RedirectToAction("Index", "Home");
            }
            else
            {
                ModelState.AddModelError("","login failure");
            }
            
            return View();
        }
        [HttpGet]
        public ActionResult Registration()
        {
            return View();
        }
        [HttpPost]
        public ActionResult Registration(log_in user)
        {
            if (ModelState.IsValid)
            {
                using (var db = new login_simpleEntities())
                {
                    var crypt = new SimpleCrypto.PBKDF2();
                    int size = crypt.SaltSize;
                    var cryptPass = crypt.Compute(user.pass);
                    log_in newUser = new log_in() 
                    { 
                        email = user.email,
                        pass = cryptPass,
                        passsalt = crypt.Salt
                    };
                    db.log_in.Add(newUser);
                    try
                    {
                        db.SaveChanges();
                    }
                    catch(Exception e)
                    {
                        Debug.Print("Here is the error! " + e.Message);
                    }
                }
            }
            return View();
        }
        public ActionResult Logout()
        {
            FormsAuthentication.SignOut();
            return RedirectToAction("Index","Home");
        }
        private bool ValidPass(string email, string password) 
        {

            var crypt = new PBKDF2();
            bool isValid = false;
            using (var db = new login_simpleEntities())
            {
                var user = db.log_in.FirstOrDefault(u => u.email == email);
                string deCryptPass = crypt.Compute(password, user.passsalt);
                bool validation = user.pass == deCryptPass;
                if (user != null)
                {
                    if (validation)
                    {
                        isValid = true;
                    }
                }
            }
            return isValid;
        }

    }
}
