var express = require("express");
const bcrypt = require("bcrypt-nodejs");
const is = require("is_js");
const Users = require("../db/models/Users");
const Response = require("../lib/Response");
const CustomError = require("../lib/Error");
const Enum = require("../config/Enum");
const UserRoles = require("../db/models/UserRoles");
const Roles = require("../db/models/Roles");
var router = express.Router();
const auth = require("../lib/auth")();
router.post("/register", async (req, res) => {
  let body = req.body;
  try {
    let user = await Users.findOne({});
    if (user) {
      return res.sendStatus(Enum.HTTP_CODES.NOT_FOUND);
    }
    if (!body.email)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Lütfen Email Değeri Giriniz"
      );
    if (is.not.email(body.email))
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Lütfen Geçerli Bir Email Değeri Giriniz "
      );

    if (!body.password)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Lütfen Şifre Değeri Giriniz"
      );
    if (!body.first_name)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Lütfen İsim Değeri Giriniz"
      );
    if (!body.last_name)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Lütfen Soyad Değeri Giriniz"
      );
    if (!body.phone_number)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Lütfen Telefon Numarası Giriniz"
      );
    if (body.password.length < Enum.PASS_LENGTH) {
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Oluşturduğunuz Şifre En Az 8 Karakter Olmalıdır"
      );
    }

    let password = bcrypt.hashSync(body.password, bcrypt.genSaltSync(8), null);

    let createdUser = await Users.create({
      email: body.email,
      password: password,
      is_active: true,
      first_name: body.first_name,
      last_name: body.last_name,
      phone_number: body.phone_number,
    });
    let role = await Roles.create({
      role_name: Enum.SUPER_ADMIN,
      is_active: true,
      created_by: createdUser._id,
    });
    await UserRoles.create({
      role_id: role._id,
      user_id: createdUser._id,
    });

    res
      .status(Enum.HTTP_CODES.CREATED)
      .json(
        Response.successResponse({ succes: true }, Enum.HTTP_CODES.CREATED)
      );
  } catch (err) {
    let errorResponse = Response.errorResponse(err);
    res.status(errorResponse.code).json(errorResponse);
  }
});
router.post("/auth", async (req, res) => {
  try {
    let { email, password } = req.body;
    Users.validateFieldsBeforeAuth(email, password);
    let user = await Users.findOne({ email });
    if (!user)
      throw new CustomError(
        Enum.HTTP_CODES.UNAUTHORIZED,
        "Email Veya Şifre Hatalı"
      );
    if (!user.validPassword(password))
      throw new CustomError(
        Enum.HTTP_CODES.UNAUTHORIZED,
        "Email Veya Kullanıcı Adı Hatalı"
      );
    let payload = {
      id: user._id,
      exp: parseInt(Date.now() / 1000) * config.JWT.EXPIRE_TIME,
    };
    let userData = {
      _id: user._id,
      first_name: user.first_name,
      last_name: user.last_name,
    };
    let token = jwt.encode(payload, config.JWT.SECRET);
    res.json(Response.successResponse({ token, user: { userData } }));
  } catch (err) {
    let errorResponse = Response.errorResponse(err);
    res.status(errorResponse.code).json(errorResponse);
  }
});
router.all("*", auth.authenticate(), (req, res, next) => {
  next();
});
router.get("/", auth.checkRoles("user_view"), async (req, res, next) => {
  try {
    let users = await Users.find({});
    res.json(Response.successResponse(users));
  } catch (err) {
    let errorResponse = Response.errorResponse(err);
    res.status(errorResponse.status).json(errorResponse);
  }
});
router.post("/add", auth.checkRoles("user_add"), async (req, res) => {
  let body = req.body;
  try {
    if (!body.email)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Lütfen Email Değeri Giriniz"
      );
    if (is.not.email(body.email))
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Lütfen Geçerli Bir Email Değeri Giriniz "
      );

    if (!body.password)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Lütfen Şifre Değeri Giriniz"
      );
    if (!body.first_name)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Lütfen İsim Değeri Giriniz"
      );
    if (!body.last_name)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Lütfen Soyad Değeri Giriniz"
      );
    if (!body.phone_number)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Lütfen Telefon Numarası Değeri Giriniz"
      );
    if (body.password.length < Enum.PASS_LENGTH) {
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Oluşturduğunuz Şifre En Az 8 Karakter Olmalıdır"
      );
    }

    if (!body.roles || !Array.isArray(body.roles) || body.roles.length == 0) {
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Kullanıcıya Rol Tanımlanmadı Rol Tanımlayınız"
      );
    }

    let roles = await Roles.find({ _id: { $in: body.roles } });

    if (roles.length == 0) {
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Kullanıcıya Rol Tanımlanmadı Rol Tanımlayınız"
      );
    }

    let password = bcrypt.hashSync(body.password, bcrypt.genSaltSync(8), null);
    let user = await Users.create({
      email: body.email,
      password: password,
      is_active: true,
      first_name: body.first_name,
      last_name: body.last_name,
      phone_number: body.phone_number,
    });
    for (let i = 0; i < roles.length; i++) {
      await UserRoles.create({
        role_id: roles[i]._id,
        user_id: user._id,
      });
    }
    res
      .status(Enum.HTTP_CODES.CREATED)
      .json(
        Response.successResponse({ succes: true }, Enum.HTTP_CODES.CREATED)
      );
  } catch (err) {
    let errorResponse = Response.errorResponse(err);
    res.status(errorResponse.code).json(errorResponse);
  }
});
router.put("/update", auth.checkRoles("user_update"), async (req, res) => {
  let body = req.body;

  try {
    let password = bcrypt.hashSync(body.password, bcrypt.genSaltSync(8), null);
    let updates = {};
    if (!body._id)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Lütfen Id Değeri Giriniz"
      );
    if (body.password && password.length >= Enum.PASS_LENGTH) {
      updates.password = bcrypt.hashSync(
        body.password,
        bcrypt.genSaltSync(8),
        null
      );
    }
    if (typeof body.is_active == "boolean") updates.is_active = body.is_active;
    if (body.first_name) updates.first_name = body.first_name;
    if (body.last_name) updates.last_name = body.last_name;
    if (body.phone_number) updates.phone_number = body.phone_number;

    if (Array.isArray(body.roles) && body.roles.length > 0) {
      let userRoles = await UserRoles.find({
        user_id: body._id,
      });
      let removedRoles = userRoles.filter((x) => !body.roles.includes(x.role_id)
      );
      let newRoles = body.roles.filter(
        (x) => !userRoles.map((r) => r.role_id).includes(x)
      );

      if (removedRoles.length > 0) {
        await UserRoles.deleteMany({_id: { $in: removedRoles.map((x) => x._id.toString()) },
      });
      }

      if (newRoles.length > 0) {
        for (let i = 0; i < newRoles.length; i++) {
          let userRole = new UserRoles({
            role_id: newRoles[i],
            user_id: body._id,
          });

          await userRole.save();
        }
      }
    }

    await Users.updateOne({ _id: body._id }, updates);
    res.json(Response.successResponse({ success: true }));
  } catch (err) {
    let errorResponse = Response.errorResponse(err);
    res.status(errorResponse.code).json(errorResponse);
  }
});
router.delete("/delete", auth.checkRoles("user_delete"), async (req, res) => {
  try {
    let body = req.body;
    if (!body._id)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Kullanıcı Silme İşlemi İçin Lütfen Kullanıcı Id Değerini Giriniz"
      );
    await Users.deleteOne({ _id: body._id });
    await UserRoles.deleteMany({ _id: body._id });
    res.json(Response.successResponse({ success: true }));
  } catch (err) {
    let errorResponse = Response.errorResponse(err);
    res.status(errorResponse.code).json(errorResponse);
  }
});
router.post("/register", async (req, res) => {
  let body = req.body;
  try {
    let user = await Users.findOne({});
    if (user) {
      return res.sendStatus(Enum.HTTP_CODES.NOT_FOUND);
    }
    if (!body.email)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Lütfen Email Değeri Giriniz"
      );
    if (is.not.email(body.email))
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Lütfen Geçerli Bir Email Değeri Giriniz "
      );

    if (!body.password)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Lütfen Şifre Değeri Giriniz"
      );
    if (!body.first_name)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Lütfen İsim Değeri Giriniz"
      );
    if (!body.last_name)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Lütfen Soyad Değeri Giriniz"
      );
    if (!body.phone_number)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Lütfen Telefon Numarası Değeri Giriniz"
      );
    if (body.password.length < Enum.PASS_LENGTH) {
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Oluşturduğunuz Şifre En Az 8 Karakter Olmalıdır"
      );
    }

    let password = bcrypt.hashSync(body.password, bcrypt.genSaltSync(8), null);

    let createdUser = await Users.create({
      email: body.email,
      password: password,
      is_active: true,
      first_name: body.first_name,
      last_name: body.last_name,
      phone_number: body.phone_number,
    });
    let role = await Roles.create({
      role_name: Enum.SUPER_ADMIN,
      is_active: true,
      created_by: createdUser._id,
    });
    await UserRoles.create({
      role_id: role._id,
      user_id: createdUser._id,
    });

    res
      .status(Enum.HTTP_CODES.CREATED)
      .json(
        Response.successResponse({ succes: true }, Enum.HTTP_CODES.CREATED)
      );
  } catch (err) {
    let errorResponse = Response.errorResponse(err);
    res.status(errorResponse.code).json(errorResponse);
  }
});
router.post("/auth", async (req, res) => {
  try {
    let { email, password } = req.body;
    Users.validateFieldsBeforeAuth(email, password);
    let user = await Users.findOne({ email });
    if (!user)
      throw new CustomError(
        Enum.HTTP_CODES.UNAUTHORIZED,
        "Email Veya Şifre Hatalı"
      );
    if (!user.validPassword(password))
      throw new CustomError(
        Enum.HTTP_CODES.UNAUTHORIZED,
        "Email Veya Kullanıcı Adı Hatalı"
      );
    let payload = {
      id: user._id,
      exp: parseInt(Date.now() / 1000) * config.JWT.EXPIRE_TIME,
    };
    let userData = {
      _id: user._id,
      first_name: user.first_name,
      last_name: user.last_name,
    };
    let token = jwt.encode(payload, config.JWT.SECRET);
    res.json(Response.successResponse({ token, user: { userData } }));
  } catch (err) {
    let errorResponse = Response.errorResponse(err);
    res.status(errorResponse.code).json(errorResponse);
  }
});
module.exports = router;
