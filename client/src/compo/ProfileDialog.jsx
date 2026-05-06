import React, { useEffect } from "react";
import { useForm } from "react-hook-form";
import ModalWrapper from "./ModalWrapper";
import { Dialog } from "@headlessui/react";
import Textbox from "./Textbox";
import Button from "./Button";
import Loading from "./Loader";
import { toast } from "sonner";
import { useUpdateUserProfileMutation } from "../redux/slices/apiSlice";
import { useDispatch } from "react-redux";
import { setCredentials } from "../redux/slices/authSlice";

const ProfileDialog = ({ open, setOpen, user }) => {
  const [updateUserProfile, { isLoading }] = useUpdateUserProfileMutation();
  const dispatch = useDispatch();

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
    if (open && user) {
      reset({
        name: user.name,
        title: user.title,
        role: user.role,
        email: user.email,
      });
    }
  }, [open, user, reset]);

  const handleOnSubmit = async (data) => {
    try {
      const response = await updateUserProfile({
        ...data,
        _id: user._id,
      }).unwrap();

      // Update Redux with new user data
      dispatch(setCredentials(response));
      toast.success("Profile updated successfully");
      setOpen(false);
    } catch (error) {
      toast.error(error?.data?.message || error?.message || "Failed to update profile");
    }
  };

  return (
    <ModalWrapper open={open} setOpen={setOpen}>
      <form onSubmit={handleSubmit(handleOnSubmit)}>
        <Dialog.Title as='h2' className='text-base font-bold leading-6 text-gray-900 mb-4'>
          UPDATE PROFILE
        </Dialog.Title>

        <div className='mt-2 flex flex-col gap-6'>
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
          <div className='py-3 mt-4 sm:flex sm:flex-row-reverse gap-4'>
            <Button
              type='submit'
              className='bg-blue-600 px-8 text-sm font-semibold text-white hover:bg-blue-700 sm:w-auto'
              label='Submit'
            />

            <Button
              type='button'
              className='bg-white px-5 text-sm font-semibold text-gray-900 sm:w-auto border'
              onClick={() => setOpen(false)}
              label='Cancel'
            />
          </div>
        )}
      </form>
    </ModalWrapper>
  );
};

export default ProfileDialog;
