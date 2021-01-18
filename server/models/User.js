const mongoose = require('mongoose')
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const saltRounds = 10

const userSchema = mongoose.Schema({
    name: {
        type: String,
        maxlength: 50
    },
    email: {
        type: String,
        trim: true,
        unique: 1
    },
    password: {
        type: String,
        minlength: 5
    },
    lastname: {
        type: String,
        maxlength: 50
    },
    role: {
        type: Number,
        default: 0
    },
    image: String,
    token: {
        type: String
    },
    tokenExp: {
        type: Number
    }
})

userSchema.pre('save', function(next) {
    var user = this;
    if(user.isModified('password')) {
        // 비밀번호 암호화 시킨다.
        bcrypt.genSalt(saltRounds, (err, salt) => {
            if(err) return next(err)

            bcrypt.hash(user.password, salt, function(err, hash) {
                if(err) return next(err)
                user.password = hash
                next()
            })
        })
    } else {
        next()
    }
})

userSchema.methods.comparePassword = function(plainPassword, callbackFunc) {
    // plainPassword 1234567 암호화된 비밀번호 $2b$10$KPEpKqTyytCZGRSc169aZuoKYLDvVVGvzyKpEYyjH52vdheyKMurO
    bcrypt.compare(plainPassword, this.password, function(err, isMatch) {
        if(err) return callbackFunc(err)
        callbackFunc(null, isMatch)
    })
}

userSchema.methods.generateToken = function(callbackFunc) {
    var user = this;
    // jsonwebtoken을 이용해서 token을 생성하기 
    var token = jwt.sign(user._id.toHexString(), 'secretToken')
    user.token = token
    user.save(function(err, user) {
        if(err) return callbackFunc(err)
        callbackFunc(null, user)
    })
}

userSchema.statics.findByToken = function(token, callbackFunc) {
    var user = this;

    // token decode
    jwt.verify(token, 'secretToken', function(err, decoded) {
        // 유저 아이디를 이용해서 유저를 찾은 다음에
        // 클라이언트에서 가져온 토큰과 데이터베이스에 보관된 토큰이 일치하는지 확인 
        console.log("decoded : " + decoded)
        console.log("token : " + token)
        user.findOne({"_id": decoded, "token": token}, function(err, user) {
            if(err) return callbackFunc(err)
            callbackFunc(null, user)
        })
    })
}

const User = mongoose.model('User', userSchema)

module.exports = { User }