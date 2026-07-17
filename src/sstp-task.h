/* SPDX-License-Identifier: GPL-2.0-or-later */
/*!
 * @brief API for handling sub-tasks
 *
 * @file sstp-task.c
 *
 * @author Copyright (C) 2011 Eivind Naess, 
 *      All Rights Reserved
 */
#ifndef __SSTP_TASK_H__
#define __SSTP_TASK_H__


typedef enum
{
    /*! 
     * @brief Redirecting standard error and output to /dev/null.
     */
    SSTP_TASK_SILENT    = 0,

    /*!
     * @brief If this flag is set, the parent's will be able to 
     *   communicate with the child using the task's standard 
     *   input/ouput descriptors.
     */
    SSTP_TASK_USEPIPE   = 1,

    /*!
     * @brief If this flag is set, the parent's task->out is connected 
     *   to the pty, and the child's stdin is connected to the tty
     */
    SSTP_TASK_USEPTY    = 2,

} sstp_task_t;



/*!
 * @brief These are declared in sstp-task.c
 */
struct sstp_task;
typedef struct sstp_task sstp_task_st;


/*!
 * @brief Initialize a task structure
 */
status_t sstp_task_new(sstp_task_st **task, sstp_task_t type);


/*! 
 * @brief Starts a task given the command line
 */
status_t sstp_task_start(sstp_task_st *task, const char *argv[]);


/*!
 * @brief Get standard output
 */
int sstp_task_stdout(sstp_task_st *task);


/*!
 * @brief Checks if a task is still running
 */
int sstp_task_alive(sstp_task_st *task);


/*! 
 * @brief Return a pinter to the pty dev
 */
const char *sstp_task_ttydev(sstp_task_st* task);


/*!
 * @brief Close all I/O descriptors
 */
void sstp_task_close(sstp_task_st *task);


/*! 
 * @brief Stops a task sending it a signal (expect SIGCHLD)
 */
status_t sstp_task_stop(sstp_task_st *task);


/*!
 * @brief Wait for the task to finish
 */
status_t sstp_task_wait(sstp_task_st *task, int *status, int flag);


/*!
 * @brief Destroys the task structure, nothing in the structure will
 *   be accessible.
 */
void sstp_task_destroy(sstp_task_st *task);


#endif
