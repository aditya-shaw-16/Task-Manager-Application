import React, { useState, useEffect } from "react";
import ModalWrapper from "../ModalWrapper";
import { Dialog } from "@headlessui/react";
import Textbox from "../Textbox";
import { useForm } from "react-hook-form";
import UserList from "./UserList";
import SelectList from "../SelectList";
import { BiImages } from "react-icons/bi";
import Button from "../Button";
import Loading from "../Loader";
import { toast } from "sonner";
import { useCreateTaskMutation, useUpdateTaskMutation } from "../../redux/slices/apiSlice";

const LISTS = ["TODO", "IN PROGRESS", "COMPLETED"];
const PRIORIRY = ["HIGH", "MEDIUM", "NORMAL", "LOW"];

const AddTask = ({ open, setOpen, task = null }) => {
  const {
    register,
    handleSubmit,
    formState: { errors },
    reset,
  } = useForm();
  const [team, setTeam] = useState([]);
  const [stage, setStage] = useState(LISTS[0]);
  const [priority, setPriority] = useState(PRIORIRY[2]);
  const [assets, setAssets] = useState([]);
  const [createTaskMutation, { isLoading: isCreating }] = useCreateTaskMutation();
  const [updateTaskMutation, { isLoading: isUpdating }] = useUpdateTaskMutation();
  const isLoading = isCreating || isUpdating;

  useEffect(() => {
    if (task && open) {
      // Pre-fill form for editing
      reset({ title: task.title, date: task.date?.split('T')[0] || '' });
      setTeam(task.team || []);
      setStage(task.stage?.toUpperCase() || LISTS[0]);
      setPriority(task.priority?.toUpperCase() || PRIORIRY[2]);
      setAssets(task.assets || []);
    } else if (open) {
      // Reset for new task
      reset({ title: '', date: '' });
      setTeam([]);
      setStage(LISTS[0]);
      setPriority(PRIORIRY[2]);
      setAssets([]);
    }
  }, [open, task, reset]);

  const submitHandler = async (data) => {
    try {
      const payload = {
        ...data,
        team,
        stage: stage.toLowerCase(),
        priority: priority.toLowerCase(),
        assets,
      };

      if (task?._id) {
        // Update existing task
        await updateTaskMutation({ id: task._id, ...payload }).unwrap();
        toast.success("Task updated successfully");
      } else {
        // Create new task
        await createTaskMutation(payload).unwrap();
        toast.success("Task created successfully");
      }
      setOpen(false);
    } catch (error) {
      toast.error(error?.data?.message || error?.message || "Failed to save task");
    }
  };

  const handleSelect = (e) => {
    setAssets(Array.from(e.target.files || []).map((file) => URL.createObjectURL(file)));
  };

  return (
    <>
      <ModalWrapper open={open} setOpen={setOpen}>
        <form onSubmit={handleSubmit(submitHandler)}>
          <Dialog.Title
            as='h2'
            className='text-base font-bold leading-6 text-gray-900 mb-4'
          >
            {task?._id ? "UPDATE TASK" : "ADD TASK"}
          </Dialog.Title>

          <div className='mt-2 flex flex-col gap-6'>
            <Textbox
              placeholder='Task Title'
              type='text'
              name='title'
              label='Task Title'
              className='w-full rounded'
              register={register("title", { required: "Title is required" })}
              error={errors.title ? errors.title.message : ""}
            />

            <UserList setTeam={setTeam} team={team} />

            <div className='flex gap-4'>
              <SelectList
                label='Task Stage'
                lists={LISTS}
                selected={stage}
                setSelected={setStage}
              />

              <div className='w-full'>
                <Textbox
                  placeholder='Date'
                  type='date'
                  name='date'
                  label='Task Date'
                  className='w-full rounded'
                  register={register("date", {
                    required: "Date is required!",
                  })}
                  error={errors.date ? errors.date.message : ""}
                />
              </div>
            </div>

            <div className='flex gap-4'>
              <SelectList
                label='Priority Level'
                lists={PRIORIRY}
                selected={priority}
                setSelected={setPriority}
              />

              <div className='w-full flex items-center justify-center mt-4'>
                <label
                  className='flex items-center gap-1 text-base text-ascent-2 hover:text-ascent-1 cursor-pointer my-4'
                  htmlFor='imgUpload'
                >
                  <input
                    type='file'
                    className='hidden'
                    id='imgUpload'
                    onChange={(e) => handleSelect(e)}
                    accept='.jpg, .png, .jpeg'
                    multiple={true}
                  />
                  <BiImages />
                  <span>Add Assets</span>
                </label>
              </div>
            </div>

            <div className='bg-gray-50 py-6 sm:flex sm:flex-row-reverse gap-4'>
              {isLoading ? (
                <div className='py-2'>
                  <Loading />
                </div>
              ) : (
                <Button
                  label='Submit'
                  type='submit'
                  className='bg-blue-600 px-8 text-sm font-semibold text-white hover:bg-blue-700  sm:w-auto'
                />
              )}

              <Button
                type='button'
                className='bg-white px-5 text-sm font-semibold text-gray-900 sm:w-auto'
                onClick={() => setOpen(false)}
                label='Cancel'
              />
            </div>
          </div>
        </form>
      </ModalWrapper>
    </>
  );
};

export default AddTask;