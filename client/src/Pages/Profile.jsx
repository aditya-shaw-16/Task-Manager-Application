import React, { useEffect } from "react";
import { useForm } from "react-hook-form";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import Button from "../compo/Button";
import Loading from "../compo/Loader";
import Textbox from "../compo/Textbox";
import { getInitials } from "../Utils";
import { useUpdateUserProfileMutation } from "../redux/slices/apiSlice";
import { setCredentials } from "../redux/slices/authSlice";

const Profile = () => {
  const { user } = useSelector((state) => state.auth);
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const [updateUserProfile, { isLoading }] = useUpdateUserProfileMutation();

  const {
    register,
    handleSubmit,
    formState: { errors },
    reset,
  } = useForm({
    defaultValues: {
      name: user?.name || "",
      title: user?.title || "",
      role: user?.role || "",
      email: user?.email || "",
    },
  });

  useEffect(() => {
    if (user) {
      reset({
        name: user.name || "",
        title: user.title || "",
        role: user.role || "",
        email: user.email || "",
      });
    }
  }, [user, reset]);

  const handleOnSubmit = async (data) => {
    try {
      const response = await updateUserProfile({
        ...data,
        _id: user._id,
      }).unwrap();

      dispatch(setCredentials(response));
      toast.success("Profile updated successfully");
    } catch (error) {
      toast.error(error?.data?.message || error?.message || "Failed to update profile");
    }
  };

  return (
    <div className='max-w-4xl mx-auto py-6'>
      <div className='bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden'>
        <div className='px-6 py-5 border-b border-gray-200 flex items-center justify-between gap-4'>
          <div>
            <p className='text-sm text-gray-500'>Account</p>
            <h1 className='text-2xl font-semibold text-gray-900'>Profile</h1>
          </div>

          <button
            type='button'
            onClick={() => navigate(-1)}
            className='text-sm font-medium text-blue-700 hover:underline'
          >
            Go back
          </button>
        </div>

        <div className='p-6 grid grid-cols-1 lg:grid-cols-[220px_1fr] gap-8'>
          <div className='flex flex-col items-center justify-start gap-4'>
            <div className='w-28 h-28 rounded-full bg-blue-600 flex items-center justify-center text-white text-4xl font-semibold'>
              {getInitials(user?.name)}
            </div>

            <div className='text-center'>
              <p className='text-lg font-semibold text-gray-900'>{user?.name}</p>
              <p className='text-sm text-gray-500'>{user?.email}</p>
              <p className='text-sm text-gray-500'>{user?.role}</p>
            </div>
          </div>

          <form onSubmit={handleSubmit(handleOnSubmit)} className='flex flex-col gap-6'>
            <div className='grid grid-cols-1 md:grid-cols-2 gap-6'>
              <Textbox
                placeholder='Full name'
                type='text'
                name='name'
                label='Full Name'
                className='w-full rounded'
                register={register("name", {
                  required: "Full name is required!",
                })}
                error={errors.name ? errors.name.message : ""}
              />

              <Textbox
                placeholder='Title'
                type='text'
                name='title'
                label='Title'
                className='w-full rounded'
                register={register("title", {
                  required: "Title is required!",
                })}
                error={errors.title ? errors.title.message : ""}
              />

              <Textbox
                placeholder='Email Address'
                type='email'
                name='email'
                label='Email Address'
                className='w-full rounded'
                register={register("email", {
                  required: "Email Address is required!",
                })}
                error={errors.email ? errors.email.message : ""}
              />

              <Textbox
                placeholder='Role'
                type='text'
                name='role'
                label='Role'
                className='w-full rounded'
                register={register("role", {
                  required: "User role is required!",
                })}
                error={errors.role ? errors.role.message : ""}
              />
            </div>

            {isLoading ? (
              <div className='py-5'>
                <Loading />
              </div>
            ) : (
              <div className='flex justify-end gap-3'>
                <Button
                  type='button'
                  className='bg-white px-5 text-sm font-semibold text-gray-900 border'
                  onClick={() => navigate(-1)}
                  label='Cancel'
                />

                <Button
                  type='submit'
                  className='bg-blue-600 px-8 text-sm font-semibold text-white hover:bg-blue-700'
                  label='Save Changes'
                />
              </div>
            )}
          </form>
        </div>
      </div>
    </div>
  );
};

export default Profile;