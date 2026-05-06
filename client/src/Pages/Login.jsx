import React, { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { useNavigate } from "react-router-dom";
import Textbox from "../compo/Textbox";
import Button from "../compo/Button";
import { useSelector } from "react-redux";
import { useDispatch } from "react-redux";
import { setCredentials } from "../redux/slices/authSlice";
import { toast } from "sonner";
import {
  useLoginUserMutation,
  useRegisterUserMutation,
} from "../redux/slices/apiSlice";

const Login = () => {
  const { user } = useSelector((state) => state.auth);
  const [isRegistering, setIsRegistering] = useState(false);
  const [loginUser, { isLoading: isLoggingIn }] = useLoginUserMutation();
  const [registerUser, { isLoading: isRegisteringUser }] = useRegisterUserMutation();
  const {
    register,
    handleSubmit,
    formState: { errors },
    reset,
  } = useForm();

  const navigate = useNavigate();
  const dispatch = useDispatch();

  const submitHandler = async (data) => {
    try {
      if (isRegistering) {
        if (data.password !== data.confirmPassword) {
          toast.error("Passwords do not match");
          return;
        }

        await registerUser({
          name: data.name,
          title: data.title,
          role: data.role,
          email: data.email,
          password: data.password,
          isAdmin: false,
        }).unwrap();

        const loggedInUser = await loginUser({
          email: data.email,
          password: data.password,
        }).unwrap();

        dispatch(setCredentials(loggedInUser));
        toast.success("Account created successfully");
        navigate("/dashboard");
        return;
      }

      const result = await loginUser({
        email: data.email,
        password: data.password,
      }).unwrap();

      dispatch(setCredentials(result));
      toast.success("Logged in successfully");
      navigate("/dashboard");
    } catch (error) {
      toast.error(error?.data?.message || error?.message || "Request failed");
    }
  };

  useEffect(() => {
    user && navigate("/dashboard");
  }, [user]);

  useEffect(() => {
    reset();
  }, [isRegistering, reset]);

  return (
    <div className='w-full min-h-screen flex items-center justify-center flex-col lg:flex-row bg-[#f3f4f6]'>
      <div className='w-full md:w-auto flex gap-0 md:gap-40 flex-col md:flex-row items-center justify-center'>
        {/* left side */}
        <div className='h-full w-full lg:w-2/3 flex flex-col items-center justify-center'>
          <div className='w-full md:max-w-lg 2xl:max-w-3xl flex flex-col items-center justify-center gap-5 md:gap-y-10 2xl:-mt-20'>
            <span className='flex gap-1 py-1 px-3 border rounded-full text-sm md:text-base bordergray-300 text-gray-600'>
              Manage all your task in one place!
            </span>
            <p className='flex flex-col gap-0 md:gap-4 text-4xl md:text-6xl 2xl:text-7xl font-black text-center text-blue-700'>
              <span>Cloud-Based</span>
              <span>Task Manager</span>
            </p>

            <div className='cell'>
              <div className='circle rotate-in-up-left'></div>
            </div>
          </div>
        </div>

        {/* right side */}
        <div className='w-full md:w-1/3 p-4 md:p-1 flex flex-col justify-center items-center'>
          <form
            onSubmit={handleSubmit(submitHandler)}
            className='form-container w-full md:w-[440px] flex flex-col gap-y-8 bg-white px-10 pt-14 pb-14'
          >
            <div className=''>
              <p className='text-blue-600 text-3xl font-bold text-center'>
                {isRegistering ? "Create account" : "Welcome back!"}
              </p>
              <p className='text-center text-base text-gray-700 '>
                {isRegistering
                  ? "Enter the details below to register a new user."
                  : "Keep all your credentials safe."}
              </p>
            </div>

            <div className='flex flex-col gap-y-5'>
              {isRegistering ? (
                <>
                  <Textbox
                    placeholder='Full name'
                    type='text'
                    name='name'
                    label='Full Name' 
                    className='w-full rounded-full'
                    register={register("name", {
                      required: "Full name is required!",
                    })}
                    error={errors.name ? errors.name.message : ""}
                  />
                  <Textbox
                    placeholder='Job title'
                    type='text'
                    name='title'
                    label='Title'
                    className='w-full rounded-full'
                    register={register("title", {
                      required: "Title is required!",
                    })}
                    error={errors.title ? errors.title.message : ""}
                  />
                  <Textbox
                    placeholder='Role'
                    type='text'
                    name='role'
                    label='Role'
                    className='w-full rounded-full'
                    register={register("role", {
                      required: "Role is required!",
                    })}
                    error={errors.role ? errors.role.message : ""}
                  />
                </>
              ) : null}

              <Textbox
                placeholder='email@example.com'
                type='email'
                name='email'
                label='Email Address'
                className='w-full rounded-full'
                register={register("email", {
                  required: "Email Address is required!",
                })}
                error={errors.email ? errors.email.message : ""}
              />
              <Textbox
                placeholder='your password'
                type='password'
                name='password'
                label='Password'
                className='w-full rounded-full'
                register={register("password", {
                  required: "Password is required!",
                })}
                error={errors.password ? errors.password.message : ""}
              />

              {isRegistering ? (
                <Textbox
                  placeholder='confirm your password'
                  type='password'
                  name='confirmPassword'
                  label='Confirm Password'
                  className='w-full rounded-full'
                  register={register("confirmPassword", {
                    required: "Please confirm your password!",
                  })}
                  error={errors.confirmPassword ? errors.confirmPassword.message : ""}
                />
              ) : null}

              {!isRegistering ? (
                <span className='text-sm text-gray-500 hover:text-blue-600 hover:underline cursor-pointer'>
                  Forget Password?
                </span>
              ) : null}

              <Button
                type='submit'
                label={
                  isRegistering
                    ? isRegisteringUser
                      ? "Creating..."
                      : "Create Account"
                    : isLoggingIn
                    ? "Signing In..."
                    : "Submit"
                }
                className='w-full h-10 bg-blue-700 text-white rounded-full'
              />

              <button
                type='button'
                onClick={() => setIsRegistering((current) => !current)}
                className='text-sm text-blue-700 hover:underline text-center'
              >
                {isRegistering
                  ? "Already have an account? Log in"
                  : "New here? Create a new user"}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default Login;