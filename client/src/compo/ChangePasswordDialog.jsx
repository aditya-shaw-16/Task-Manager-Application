import React from "react";
import { useForm } from "react-hook-form";
import ModalWrapper from "./ModalWrapper";
import { Dialog } from "@headlessui/react";
import Textbox from "./Textbox";
import Button from "./Button";
import Loading from "./Loader";
import { toast } from "sonner";
import { useChangePasswordMutation } from "../redux/slices/apiSlice";

const ChangePasswordDialog = ({ open, setOpen }) => {
  const [changePassword, { isLoading }] = useChangePasswordMutation();

  const {
    register,
    handleSubmit,
    formState: { errors },
    reset,
    watch,
  } = useForm({
    defaultValues: {
      password: "",
      confirmPassword: "",
    },
  });

  const password = watch("password");

  const handleOnSubmit = async (data) => {
    try {
      if (data.password !== data.confirmPassword) {
        toast.error("Passwords do not match");
        return;
      }

      await changePassword({
        password: data.password,
      }).unwrap();

      toast.success("Password changed successfully");
      reset();
      setOpen(false);
    } catch (error) {
      toast.error(error?.data?.message || error?.message || "Failed to change password");
    }
  };

  return (
    <ModalWrapper open={open} setOpen={setOpen}>
      <form onSubmit={handleSubmit(handleOnSubmit)}>
        <Dialog.Title as='h2' className='text-base font-bold leading-6 text-gray-900 mb-4'>
          CHANGE PASSWORD
        </Dialog.Title>

        <div className='mt-2 flex flex-col gap-6'>
          <Textbox
            placeholder='New Password'
            type='password'
            name='password'
            label='New Password'
            className='w-full rounded'
            register={register("password", {
              required: "Password is required!",
              minLength: {
                value: 6,
                message: "Password must be at least 6 characters",
              },
            })}
            error={errors.password ? errors.password.message : ""}
          />

          <Textbox
            placeholder='Confirm Password'
            type='password'
            name='confirmPassword'
            label='Confirm Password'
            className='w-full rounded'
            register={register("confirmPassword", {
              required: "Please confirm your password!",
              validate: (value) =>
                value === password || "Passwords do not match",
            })}
            error={errors.confirmPassword ? errors.confirmPassword.message : ""}
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
              onClick={() => {
                reset();
                setOpen(false);
              }}
              label='Cancel'
            />
          </div>
        )}
      </form>
    </ModalWrapper>
  );
};

export default ChangePasswordDialog;
