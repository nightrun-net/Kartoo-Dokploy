const path = require('path');

require('dotenv').config({
  path: path.resolve(__dirname, '.env'),
});


const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

const app = express();

app.set('trust proxy', 1);

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '20kb' }));

const {
  PORT = 3000,
  OTPIQ_API_KEY,
  OTPIQ_PROVIDER = 'whatsapp',
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  SUPABASE_ANON_KEY,
  OTP_HASH_SECRET,
} = process.env;

/* ============================================
   CHECK ENVIRONMENT VARIABLES
============================================ */

const missingVariables = [
  ['OTPIQ_API_KEY', OTPIQ_API_KEY],
  ['SUPABASE_URL', SUPABASE_URL],
  ['SUPABASE_SERVICE_ROLE_KEY', SUPABASE_SERVICE_ROLE_KEY],
  ['SUPABASE_ANON_KEY', SUPABASE_ANON_KEY],
  ['OTP_HASH_SECRET', OTP_HASH_SECRET],
]
  .filter(([, value]) => !value)
  .map(([name]) => name);

if (missingVariables.length > 0) {
  throw new Error(
    `Missing environment variables: ${missingVariables.join(', ')}`
  );
}

if (OTP_HASH_SECRET.length < 32) {
  throw new Error(
    'OTP_HASH_SECRET must contain at least 32 characters.'
  );
}

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false,
    },
  }
);

const sendOtpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message:
      'Too many OTP requests. Please try again after 10 minutes.',
  },
});

const verifyOtpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message:
      'Too many verification attempts. Please try again later.',
  },
});


const supabaseLogin = createClient(
  SUPABASE_URL,
  SUPABASE_ANON_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false,
    },
  }
);


function normalizeIraqiPhone(value) {
  let digits = String(value || '').replace(/\D/g, '');

  // 07501234567
  if (/^07\d{9}$/.test(digits)) {
    digits = `964${digits.slice(1)}`;
  }

  // 7501234567
  else if (/^7\d{9}$/.test(digits)) {
    digits = `964${digits}`;
  }

  // Must now be: 9647501234567
  if (!/^9647\d{9}$/.test(digits)) {
    return null;
  }

  return {
    local: `0${digits.slice(3)}`,
    e164: `+${digits}`,
    otpiq: digits,
  };
}


function isStrongPassword(password) {
  return (
    typeof password === 'string' &&
    password.length >= 8 &&
    /[A-Z]/.test(password) &&
    /[0-9]/.test(password) &&
    /[!@#$%^&*(),.?":{}|<>]/.test(password)
  );
}

function createOtpHash({ requestId, phone, code }) {
  return crypto
    .createHmac('sha256', OTP_HASH_SECRET)
    .update(`${requestId}:${phone}:${code}`)
    .digest('hex');
}


async function sendThroughOtpiq({ phoneNumber, code }) {
  const controller = new AbortController();

  const timeoutId = setTimeout(() => {
    controller.abort();
  }, 20000);

  try {
    const response = await fetch(
      'https://api.otpiq.com/api/sms',
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${OTPIQ_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          phoneNumber,
          smsType: 'verification',
          verificationCode: code,
          provider: OTPIQ_PROVIDER,
        }),
        signal: controller.signal,
      }
    );

    const result = await response.json().catch(() => null);

    if (!response.ok) {
      console.error('OTPIQ response:', result);

      const error = new Error(
        result?.message ||
          result?.error ||
          'OTPIQ could not send the verification code.'
      );

      error.statusCode = response.status;
      throw error;
    }

    return result || {};
  } catch (error) {
    if (error.name === 'AbortError') {
      throw new Error('OTPIQ request timed out.');
    }

    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

app.get('/api/health', async (req, res) => {
  try {
    const { error } = await supabase
      .from('users')
      .select('id', {
        count: 'exact',
        head: true,
      });

    if (error) {
      throw error;
    }

    return res.json({
      success: true,
      message:
        'Registration API, OTPIQ and Supabase configuration are ready.',
    });
  } catch (error) {
    console.error('Health error:', error);

    return res.status(503).json({
      success: false,
      message:
        'The API is running, but Supabase is not connected.',
      error: error.message,
    });
  }
});


app.post(
  '/api/register/send-otp',
  sendOtpLimiter,
  async (req, res) => {
    let newOtpId = null;

    try {
      const normalizedPhone = normalizeIraqiPhone(
        req.body.phone
      );

      if (!normalizedPhone) {
        return res.status(400).json({
          success: false,
          message:
            'Enter a valid Iraqi number: 07XXXXXXXXX',
        });
      }

      const {
        data: existingUser,
        error: existingUserError,
      } = await supabase
        .from('users')
        .select('id')
        .eq('phone', normalizedPhone.e164)
        .maybeSingle();

      if (existingUserError) {
        throw existingUserError;
      }

      if (existingUser) {
        return res.status(409).json({
          success: false,
          message:
            'This phone number is already registered.',
        });
      }


      const {
        data: latestOtp,
        error: latestOtpError,
      } = await supabase
        .from('registration_otps')
        .select('created_at')
        .eq('phone', normalizedPhone.e164)
        .is('used_at', null)
        .order('created_at', {
          ascending: false,
        })
        .limit(1)
        .maybeSingle();

      if (latestOtpError) {
        throw latestOtpError;
      }

      if (latestOtp?.created_at) {
        const secondsSinceLastRequest = Math.floor(
          (
            Date.now() -
            new Date(latestOtp.created_at).getTime()
          ) / 1000
        );

        if (secondsSinceLastRequest < 40) {
          return res.status(429).json({
            success: false,
            message: `Wait ${
              40 - secondsSinceLastRequest
            } seconds before requesting another code.`,
          });
        }
      }

      const { error: invalidateError } = await supabase
        .from('registration_otps')
        .update({
          used_at: new Date().toISOString(),
        })
        .eq('phone', normalizedPhone.e164)
        .is('used_at', null);

      if (invalidateError) {
        throw invalidateError;
      }

      const code = crypto
        .randomInt(100000, 1000000)
        .toString();

      const requestId = crypto.randomUUID();

      const codeHash = createOtpHash({
        requestId,
        phone: normalizedPhone.e164,
        code,
      });

      const expiresAt = new Date(
        Date.now() + 5 * 60 * 1000
      ).toISOString();


      const {
        data: otpRow,
        error: otpInsertError,
      } = await supabase
        .from('registration_otps')
        .insert({
          id: requestId,
          phone: normalizedPhone.e164,
          code_hash: codeHash,
          expires_at: expiresAt,
          max_attempts: 5,
        })
        .select('id')
        .single();

      if (otpInsertError) {
        throw otpInsertError;
      }

      newOtpId = otpRow.id;


      const otpiqResult = await sendThroughOtpiq({
        phoneNumber: normalizedPhone.otpiq,
        code,
      });

      const providerMessageId =
        otpiqResult.smsId ||
        otpiqResult.id ||
        otpiqResult.messageId ||
        null;

      if (providerMessageId) {
        const { error: messageUpdateError } =
          await supabase
            .from('registration_otps')
            .update({
              provider_message_id: String(
                providerMessageId
              ),
            })
            .eq('id', newOtpId);

        if (messageUpdateError) {
          console.error(
            'Could not save provider message ID:',
            messageUpdateError
          );
        }
      }

      return res.status(200).json({
        success: true,
        message:
          'The verification code was sent through WhatsApp.',
        requestId: newOtpId,
        expiresIn: 300,
        resendAfter: 40,
      });
    } catch (error) {
      console.error('Send OTP error:', error);


      if (newOtpId) {
        await supabase
          .from('registration_otps')
          .delete()
          .eq('id', newOtpId);
      }

      return res.status(
        Number.isInteger(error.statusCode)
          ? error.statusCode
          : 500
      ).json({
        success: false,
        message:
          error.message ||
          'Could not send the WhatsApp verification code.',
      });
    }
  }
);

app.post(
  '/api/register/verify',
  verifyOtpLimiter,
  async (req, res) => {
    let createdAuthUserId = null;

    try {
      const {
        requestId,
        code,
        firstName,
        lastName,
        city,
        district,
        homeAddress,
        password,
      } = req.body;

      const normalizedPhone = normalizeIraqiPhone(
        req.body.phone
      );

      if (!normalizedPhone) {
        return res.status(400).json({
          success: false,
          message: 'The phone number is invalid.',
        });
      }

      if (
        typeof requestId !== 'string' ||
        !/^[0-9a-f-]{36}$/i.test(requestId)
      ) {
        return res.status(400).json({
          success: false,
          message:
            'The OTP request is invalid. Request a new code.',
        });
      }

      if (!/^\d{6}$/.test(String(code || ''))) {
        return res.status(400).json({
          success: false,
          message:
            'Enter the complete six-digit code.',
        });
      }

      if (
        !String(firstName || '').trim() ||
        !String(lastName || '').trim() ||
        !String(city || '').trim() ||
        !String(district || '').trim() ||
        !String(homeAddress || '').trim()
      ) {
        return res.status(400).json({
          success: false,
          message:
            'The registration information is incomplete.',
        });
      }

      if (!isStrongPassword(password)) {
        return res.status(400).json({
          success: false,
          message:
            'Password must contain at least 8 characters, one capital letter, one number and one symbol.',
        });
      }


      const codeHash = createOtpHash({
        requestId,
        phone: normalizedPhone.e164,
        code: String(code),
      });

      const {
        data: claimResult,
        error: claimError,
      } = await supabase.rpc(
        'claim_registration_otp',
        {
          p_request_id: requestId,
          p_phone: normalizedPhone.e164,
          p_code_hash: codeHash,
        }
      );

      if (claimError) {
        throw claimError;
      }

      const claim = Array.isArray(claimResult)
        ? claimResult[0]
        : claimResult;

      if (!claim?.ok) {
        const errorMessages = {
          not_found:
            'Request a new verification code.',
          already_used:
            'This verification code was already used.',
          expired:
            'The verification code expired. Request a new code.',
          max_attempts:
            'Too many incorrect attempts. Request a new code.',
          invalid_code:
            'The verification code is incorrect.',
        };

        return res.status(400).json({
          success: false,
          message:
            errorMessages[claim?.reason] ||
            'The verification code could not be verified.',
        });
      }



      const {
        data: existingProfile,
        error: existingProfileError,
      } = await supabase
        .from('users')
        .select('id')
        .eq('phone', normalizedPhone.e164)
        .maybeSingle();

      if (existingProfileError) {
        throw existingProfileError;
      }

      if (existingProfile) {
        return res.status(409).json({
          success: false,
          message:
            'This phone number is already registered.',
        });
      }


      const {
        data: authData,
        error: authError,
      } = await supabase.auth.admin.createUser({
        phone: normalizedPhone.e164,
        password,
        phone_confirm: true,
        user_metadata: {
          first_name: String(firstName).trim(),
          last_name: String(lastName).trim(),
        },
      });

      if (authError) {
        if (
          /already|registered|exists|duplicate/i.test(
            authError.message || ''
          )
        ) {
          return res.status(409).json({
            success: false,
            message:
              'This phone number is already registered.',
          });
        }

        throw authError;
      }

      createdAuthUserId = authData.user.id;


      const { error: profileError } = await supabase
        .from('users')
        .insert({
          id: createdAuthUserId,
          first_name: String(firstName).trim(),
          last_name: String(lastName).trim(),
          phone: normalizedPhone.e164,
          city: String(city).trim(),
          district: String(district).trim(),
          home_address: String(homeAddress).trim(),
          phone_verified: true,
        });

      if (profileError) {

        await supabase.auth.admin.deleteUser(
          createdAuthUserId,
          false
        );

        createdAuthUserId = null;

        throw profileError;
      }

      return res.status(201).json({
        success: true,
        userId: createdAuthUserId,
        message:
          'Your phone was verified and your account was created successfully.',
      });
    } catch (error) {
      console.error(
        'Verify and register error:',
        error
      );

      if (createdAuthUserId) {
        await supabase.auth.admin.deleteUser(
          createdAuthUserId,
          false
        );
      }

      return res.status(500).json({
        success: false,
        message:
          error.message ||
          'Could not verify the code or create the account.',
      });
    }
  }
);

app.post(
  '/auth/forgot-password/send-otp',
  sendOtpLimiter,
  async (req, res) => {
    let newOtpId = null;

    try {
      const normalizedPhone =
        normalizeIraqiPhone(
          req.body.phone
        );

      if (!normalizedPhone) {
        return res.status(400).json({
          success: false,
          message:
            'Enter a valid Iraqi number: 07XXXXXXXXX',
        });
      }

      const {
        data: profile,
        error: profileError,
      } =
        await supabase
          .from('users')
          .select('id, phone')
          .eq(
            'phone',
            normalizedPhone.e164
          )
          .maybeSingle();

      if (profileError) {
        throw profileError;
      }

      if (!profile) {
        return res.status(404).json({
          success: false,
          message:
            'No account was found with this phone number.',
        });
      }

      const {
        data: latestOtp,
        error: latestOtpError,
      } =
        await supabase
          .from(
            'password_reset_otps'
          )
          .select('created_at')
          .eq(
            'phone',
            normalizedPhone.e164
          )
          .is(
            'used_at',
            null
          )
          .order(
            'created_at',
            {
              ascending: false,
            }
          )
          .limit(1)
          .maybeSingle();

      if (latestOtpError) {
        throw latestOtpError;
      }

      if (
        latestOtp
          ?.created_at
      ) {
        const secondsSinceLastRequest =
          Math.floor(
            (
              Date.now() -
              new Date(
                latestOtp.created_at
              ).getTime()
            ) /
            1000
          );

        if (
          secondsSinceLastRequest <
          40
        ) {
          return res
            .status(429)
            .json({
              success: false,
              message:
                `Wait ${
                  40 -
                  secondsSinceLastRequest
                } seconds before requesting another code.`,
            });
        }
      }

      const {
        error:
          invalidateError,
      } =
        await supabase
          .from(
            'password_reset_otps'
          )
          .update({
            used_at:
              new Date()
                .toISOString(),
          })
          .eq(
            'phone',
            normalizedPhone.e164
          )
          .is(
            'used_at',
            null
          );

      if (
        invalidateError
      ) {
        throw invalidateError;
      }

      const code =
        crypto
          .randomInt(
            100000,
            1000000
          )
          .toString();

      const requestId =
        crypto.randomUUID();

      const codeHash =
        createOtpHash({
          requestId,
          phone:
            normalizedPhone.e164,
          code,
        });

      const expiresAt =
        new Date(
          Date.now() +
          5 * 60 * 1000
        ).toISOString();

      const {
        data: otpRow,
        error:
          otpInsertError,
      } =
        await supabase
          .from(
            'password_reset_otps'
          )
          .insert({
            id:
              requestId,

            user_id:
              profile.id,

            phone:
              normalizedPhone.e164,

            code_hash:
              codeHash,

            expires_at:
              expiresAt,

            attempts:
              0,

            max_attempts:
              5,
          })
          .select('id')
          .single();

      if (
        otpInsertError
      ) {
        throw otpInsertError;
      }

      newOtpId =
        otpRow.id;

      const otpiqResult =
        await sendThroughOtpiq({
          phoneNumber:
            normalizedPhone.otpiq,

          code,
        });

      const providerMessageId =
        otpiqResult.smsId ||
        otpiqResult.id ||
        otpiqResult.messageId ||
        null;

      if (
        providerMessageId
      ) {
        await supabase
          .from(
            'password_reset_otps'
          )
          .update({
            provider_message_id:
              String(
                providerMessageId
              ),
          })
          .eq(
            'id',
            newOtpId
          );
      }

      return res
        .status(200)
        .json({
          success: true,

          message:
            'The verification code was sent through WhatsApp.',

          requestId:
            newOtpId,

          expiresIn:
            300,

          resendAfter:
            40,
        });
    } catch (error) {
      console.error(
        'Forgot password send OTP error:',
        error
      );

      if (
        newOtpId
      ) {
        await supabase
          .from(
            'password_reset_otps'
          )
          .delete()
          .eq(
            'id',
            newOtpId
          );
      }

      return res
        .status(
          Number.isInteger(
            error.statusCode
          )
            ? error.statusCode
            : 500
        )
        .json({
          success: false,

          message:
            error.message ||
            'Could not send password reset OTP.',
        });
    }
  }
);

app.post(
  '/auth/forgot-password/verify-otp',
  verifyOtpLimiter,
  async (req, res) => {
    try {
      const normalizedPhone =
        normalizeIraqiPhone(
          req.body.phone
        );

      const otp =
        String(
          req.body.otp ||
          ''
        );

      if (!normalizedPhone) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              'The phone number is invalid.',
          });
      }

      if (
        !/^\d{6}$/.test(
          otp
        )
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              'Enter the complete six-digit code.',
          });
      }

      const {
        data: otpRow,
        error: otpError,
      } =
        await supabase
          .from(
            'password_reset_otps'
          )
          .select('*')
          .eq(
            'phone',
            normalizedPhone.e164
          )
          .is(
            'used_at',
            null
          )
          .order(
            'created_at',
            {
              ascending: false,
            }
          )
          .limit(1)
          .maybeSingle();

      if (
        otpError
      ) {
        throw otpError;
      }

      if (
        !otpRow
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              'Request a new verification code.',
          });
      }

      if (
        new Date(
          otpRow.expires_at
        ).getTime() <=
        Date.now()
      ) {
        await supabase
          .from(
            'password_reset_otps'
          )
          .update({
            used_at:
              new Date()
                .toISOString(),
          })
          .eq(
            'id',
            otpRow.id
          );

        return res
          .status(400)
          .json({
            success: false,
            message:
              'The verification code expired.',
          });
      }

      const attempts =
        Number(
          otpRow.attempts ||
          0
        );

      const maxAttempts =
        Number(
          otpRow.max_attempts ||
          5
        );

      if (
        attempts >=
        maxAttempts
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              'Too many incorrect attempts. Request a new code.',
          });
      }

      const expectedHash =
        createOtpHash({
          requestId:
            otpRow.id,

          phone:
            normalizedPhone.e164,

          code:
            otp,
        });

      const valid =
        crypto.timingSafeEqual(
          Buffer.from(
            expectedHash,
            'hex'
          ),
          Buffer.from(
            otpRow.code_hash,
            'hex'
          )
        );

      if (
        !valid
      ) {
        const newAttempts =
          attempts + 1;

        await supabase
          .from(
            'password_reset_otps'
          )
          .update({
            attempts:
              newAttempts,

            used_at:
              newAttempts >=
              maxAttempts
                ? new Date()
                    .toISOString()
                : null,
          })
          .eq(
            'id',
            otpRow.id
          );

        return res
          .status(400)
          .json({
            success: false,
            message:
              newAttempts >=
              maxAttempts
                ? 'Too many incorrect attempts. Request a new code.'
                : 'The verification code is incorrect.',
          });
      }

      const resetToken =
        crypto
          .randomBytes(
            32
          )
          .toString('hex');

      const resetTokenHash =
        crypto
          .createHmac(
            'sha256',
            OTP_HASH_SECRET
          )
          .update(
            resetToken
          )
          .digest('hex');

      const resetTokenExpiresAt =
        new Date(
          Date.now() +
          10 * 60 * 1000
        ).toISOString();

      const {
        error: updateError,
      } =
        await supabase
          .from(
            'password_reset_otps'
          )
          .update({
            verified_at:
              new Date()
                .toISOString(),

            reset_token_hash:
              resetTokenHash,

            reset_token_expires_at:
              resetTokenExpiresAt,
          })
          .eq(
            'id',
            otpRow.id
          );

      if (
        updateError
      ) {
        throw updateError;
      }

      return res.json({
        success: true,

        resetToken,

        expiresIn:
          600,
      });
    } catch (error) {
      console.error(
        'Forgot password verify OTP error:',
        error
      );

      return res
        .status(500)
        .json({
          success: false,

          message:
            error.message ||
            'Could not verify the password reset OTP.',
        });
    }
  }
);

app.post(
  '/auth/forgot-password/reset-password',
  verifyOtpLimiter,
  async (req, res) => {
    try {
      const normalizedPhone =
        normalizeIraqiPhone(
          req.body.phone
        );

      const resetToken =
        String(
          req.body.resetToken ||
          ''
        );

      const newPassword =
        String(
          req.body.newPassword ||
          ''
        );

      if (!normalizedPhone) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              'The phone number is invalid.',
          });
      }

      if (
        !resetToken
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              'The password reset session is invalid.',
          });
      }

      if (
        !isStrongPassword(
          newPassword
        )
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              'Password must contain at least 8 characters, one capital letter, one number and one symbol.',
          });
      }

      const resetTokenHash =
        crypto
          .createHmac(
            'sha256',
            OTP_HASH_SECRET
          )
          .update(
            resetToken
          )
          .digest('hex');

      const {
        data: otpRow,
        error: otpError,
      } =
        await supabase
          .from(
            'password_reset_otps'
          )
          .select(
            'id, user_id, reset_token_hash, reset_token_expires_at, used_at, verified_at'
          )
          .eq(
            'phone',
            normalizedPhone.e164
          )
          .eq(
            'reset_token_hash',
            resetTokenHash
          )
          .is(
            'used_at',
            null
          )
          .order(
            'created_at',
            {
              ascending: false,
            }
          )
          .limit(1)
          .maybeSingle();

      if (
        otpError
      ) {
        throw otpError;
      }

      if (
        !otpRow ||
        !otpRow.verified_at
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              'The password reset session is invalid.',
          });
      }

      if (
        !otpRow
          .reset_token_expires_at ||
        new Date(
          otpRow
            .reset_token_expires_at
        ).getTime() <=
        Date.now()
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              'The password reset session expired. Request a new code.',
          });
      }

      const {
        error:
          passwordUpdateError,
      } =
        await supabase.auth
          .admin
          .updateUserById(
            otpRow.user_id,
            {
              password:
                newPassword,
            }
          );

      if (
        passwordUpdateError
      ) {
        throw passwordUpdateError;
      }

      const {
        error:
          markUsedError,
      } =
        await supabase
          .from(
            'password_reset_otps'
          )
          .update({
            used_at:
              new Date()
                .toISOString(),
          })
          .eq(
            'id',
            otpRow.id
          );

      if (
        markUsedError
      ) {
        console.error(
          'Could not mark reset OTP as used:',
          markUsedError
        );
      }

      return res.json({
        success: true,

        message:
          'Password changed successfully.',
      });
    } catch (error) {
      console.error(
        'Forgot password reset error:',
        error
      );

      return res
        .status(500)
        .json({
          success: false,

          message:
            error.message ||
            'Could not reset the password.',
        });
    }
  }
);


const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many login requests. Try again later."
  }
});

const loginAuthClient = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false
    }
  }
);

function normalizeLoginPhone(input) {
  const digits = String(input || "").replace(/\D/g, "");

  if (/^07\d{9}$/.test(digits)) {
    return `+964${digits.slice(1)}`;
  }

  if (/^9647\d{9}$/.test(digits)) {
    return `+${digits}`;
  }

  if (/^7\d{9}$/.test(digits)) {
    return `+964${digits}`;
  }

  throw new Error("Invalid phone number");
}


const loginQueues = new Map();

async function withLoginLock(phone, operation) {
  const previous = loginQueues.get(phone) || Promise.resolve();

  let release;
  const current = new Promise((resolve) => {
    release = resolve;
  });

  const tail = previous.then(() => current);
  loginQueues.set(phone, tail);

  await previous;

  try {
    return await operation();
  } finally {
    release();

    if (loginQueues.get(phone) === tail) {
      loginQueues.delete(phone);
    }
  }
}


app.post("/api/auth/login", loginLimiter, async (req, res) => {
  try {
    const phone = normalizeLoginPhone(req.body?.phone);
    const password = req.body?.password;
    return await withLoginLock(phone, async () => {
    if (typeof password !== "string" ||
        password.length < 1 ||
        password.length > 1024) {
      return res.status(400).json({
        success: false,
        message: "Invalid login credentials"
      });
    }

    const { data: lock, error: lockError } =
      await supabase.rpc("check_login_attempt_lock", {
        p_phone: phone
      });

    if (lockError) throw lockError;

    if (lock?.locked) {
      return res.status(429).json({
        success: false,
        message: "Login temporarily locked",
        lockedUntil: lock.locked_until
      });
    }

    const { data: authData, error: authError } =
      await supabaseLogin.auth.signInWithPassword({
        phone,
        password
      });

    if (authError || !authData?.user || !authData?.session) {
      const { data: failed, error: failedError } =
        await supabase.rpc("record_login_failure", {
          p_phone: phone
        });

      if (failedError) throw failedError;

      return res.status(401).json({
        success: false,
        message: "Invalid login credentials",
        attemptsLeft: failed?.attempts_left,
        lockedUntil: failed?.locked_until
      });
    }
      

    const user = authData.user;

    const { data: profile, error: profileError } =
      await supabase
        .from("users")
        .select("id, phone, is_banned, login_locked_until")
        .eq("id", user.id)
        .maybeSingle();

    if (profileError) throw profileError;

    if (!profile ||
        profile.phone !== phone ||
        profile.is_banned ||
        (profile.login_locked_until &&
         new Date(profile.login_locked_until) > new Date())) {
      return res.status(403).json({
        success: false,
        message: "Account unavailable"
      });
    }

    const { error: clearError } =
      await supabase.rpc("clear_login_failures", {
        p_phone: phone
      });

    if (clearError) throw clearError;

    return res.json({
      success: true,
      user: {
        id: user.id,
        phone: profile.phone
      },
      session: {
        access_token: authData.session.access_token,
        refresh_token: authData.session.refresh_token,
        expires_at: authData.session.expires_at
      }
    });
  }); // End withLoginLock

  } catch (error) {
    console.error("Login endpoint error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Login temporarily unavailable"
    });
  }
});


app.listen(PORT, '0.0.0.0', () => {
  console.log(
    `Registration API is running on port ${PORT}`
  );
});
