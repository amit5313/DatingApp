using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;
        public AccountController(DataContext context, ITokenService tokenService)
        {
            _tokenService = tokenService;
            _context = context;

        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDtos>> Register(RegisterDto registerDto)
        {

            if (await UserExists(registerDto.Username))
            {
                return BadRequest("Username is taken");
            }
            using var hmac = new HMACSHA512();
            var user = new AppUser
            {
                UserName = registerDto.Username.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                PasswordSalt = hmac.Key
            };
            //Adds tracking to Entity Fraework
            _context.Users.Add(user);

            //Saves users into databse async
            await _context.SaveChangesAsync();

            return new UserDtos
            {
                Username=user.UserName,
                Token=_tokenService.CreateToken(user)
            };


        }
        private async Task<bool> UserExists(string username)
        {
            return await _context.Users.AnyAsync(x => x.UserName == username.ToLower());
        }


        [HttpPost("login")]
        public async Task<ActionResult<UserDtos>> Login(LoginDto logindto)
        {
            var user = await _context.Users.SingleOrDefaultAsync(x => x.UserName == logindto.Username.ToLower());

            if (user == null) return Unauthorized("Invalid User");

            using var hmac = new HMACSHA512(user.PasswordSalt);
            var ComputeHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(logindto.Password));

            for (int i = 0; i < ComputeHash.Length; i++)
            {

                if (ComputeHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid password");
            }
            //return user;

            return new UserDtos
            {
                Username=user.UserName,
                Token=_tokenService.CreateToken(user)
            };
        }

    }



}