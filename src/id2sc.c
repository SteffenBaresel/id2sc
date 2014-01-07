/*****************************************************************************
 *
 * id2sc.c - kVASy(R) System Control Broker Module
 *
 * Copyright (c) 1999-2009 Ethan Galstad (egalstad@nagios.org)
 * Copyright (c) 2009-2013 Icinga Development Team (http://www.icinga.org)
 *               2013      Steffen Baresel - SIV.AG (www.siv.de)
 *
 * Description:
 *
 * Dieses Modul erfasst die Überwachungsdaten der Icinga/Nagios Installation.
 *
 * Instructions:
 *
 * Compile with the following command:
 *
 *     gcc -shared -o id2sc.o id2sc.c
 *
 *****************************************************************************/

/* include system header files */
#include <stdio.h>
#include <assert.h>
#include <zdb.h>

#include "../nagios/config.h"

#define NSCORE
#include "../nagios/objects.h"
#include "../nagios/nagios.h"
#include "../nagios/nebstructs.h"
#include "../nagios/neberrors.h"
#include "../nagios/broker.h"
#include "../nagios/nebmodules.h"
#include "../nagios/nebcallbacks.h"
#include "../nagios/protoapi.h"

#define MAX_BUFLEN		49152
#define MAX_TEXT_LEN		32768
#define IDO_TRUE		1
#define IDO_FALSE		0
#define IDO_ERROR		-1
#define IDO_OK			0

/* specify event broker API version (required) */
NEB_API_VERSION(CURRENT_NEB_API_VERSION);

/*
 * Declarations
 */

void *id2sc_module_handle = NULL;

void id2sc_reminder_message(char *);
int id2sc_handle_data(int, void *);

int id2sc_write_to_log(char *);
void strip_buffer(char *);
char *escape_buffer(char *);
char *unescape_buffer(char *);
int error_message(char *);
int process_module_args(char *);
int process_config_var(char *);
int process_config_file(char *);

char *pgurl = NULL;
char *idname = NULL;
char *lgfile = NULL;

ConnectionPool_T pool;
URL_T url_t;
Connection_T con;

int dump_customvar_status = IDO_FALSE;

/* MMAPFILE structure - used for reading files via mmap() */
typedef struct ido_mmapfile_struct{
    char *path;
    int mode;
    int fd;
    unsigned long file_size;
    unsigned long current_position;
    unsigned long current_line;
    void *mmap_buf;
}ido_mmapfile;

ido_mmapfile *ido_mmap_fopen(char *);
int ido_mmap_fclose(ido_mmapfile *);
char *ido_mmap_fgets(ido_mmapfile *);
void strip(char *);

/*
 * this function gets called when the module is loaded by the event broker
 */

int nebmodule_init(int flags, char *args, nebmodule *handle) {
	char temp_buffer[MAX_BUFLEN];
	/*time_t current_time;
	unsigned long interval;*/

	/* save our handle */
	id2sc_module_handle = handle;

	/* set some info - this is completely optional, as Icinga doesn't do anything with this data */
	neb_set_module_info(id2sc_module_handle, NEBMODULE_MODINFO_AUTHOR, "Steffen Baresel");
	neb_set_module_info(id2sc_module_handle, NEBMODULE_MODINFO_TITLE, "id2sc - Icinga Data To System Control");
	neb_set_module_info(id2sc_module_handle, NEBMODULE_MODINFO_VERSION, "System Control Version 3");
	neb_set_module_info(id2sc_module_handle, NEBMODULE_MODINFO_LICENSE, "kVASy(R) SIV.AG");
	neb_set_module_info(id2sc_module_handle, NEBMODULE_MODINFO_DESC, "Icinga Data To System Control Data Source");

	/* log module info to the Icinga log file */
	write_to_all_logs("id2sc: Steffen Baresel SIV.AG 2013 Mail: kvasysystemcontrol@siv.de", NSLOG_INFO_MESSAGE);

	/* log a message to the Icinga log file */
	snprintf(temp_buffer, sizeof(temp_buffer) - 1, "id2sc: startup completed\n");
	temp_buffer[sizeof(temp_buffer)-1] = '\x0';
	write_to_all_logs(temp_buffer, NSLOG_INFO_MESSAGE);

	/* log a reminder message every 15 minutes (how's that for annoying? :-)) */
	/*time(&current_time);
	interval = 900;
	schedule_new_event(EVENT_USER_FUNCTION, TRUE, current_time + interval, TRUE, interval, NULL, TRUE, (void *)id2sc_reminder_message, "How about you?", 0);*/

	/* process arguments */
	if (process_module_args(args) == IDO_ERROR) {
		error_message("id2sc: An error occurred while attempting to process module arguments.");
		return -1;
	}

	/* open connection pool to postgresl */

	url_t = URL_new(pgurl);
	pool = ConnectionPool_new(url_t);
	ConnectionPool_start(pool);

	/* register to be notified of certain events... */
	
	neb_register_callback(NEBCALLBACK_AGGREGATED_STATUS_DATA, id2sc_module_handle, 0, id2sc_handle_data);
	neb_register_callback(NEBCALLBACK_SERVICE_STATUS_DATA, id2sc_module_handle, 0, id2sc_handle_data);
	neb_register_callback(NEBCALLBACK_HOST_STATUS_DATA, id2sc_module_handle, 0, id2sc_handle_data);
	neb_register_callback(NEBCALLBACK_PROGRAM_STATUS_DATA, id2sc_module_handle, 0, id2sc_handle_data);
	neb_register_callback(NEBCALLBACK_STATE_CHANGE_DATA, id2sc_module_handle, 0, id2sc_handle_data);

	return 0;
}


/* this function gets called when the module is unloaded by the event broker */
int nebmodule_deinit(int flags, int reason) {
	char temp_buffer[MAX_BUFLEN];

	/* deregister for all events we previously registered for... */
	neb_deregister_callback(NEBCALLBACK_AGGREGATED_STATUS_DATA, id2sc_handle_data);
	neb_deregister_callback(NEBCALLBACK_SERVICE_STATUS_DATA, id2sc_handle_data);
	neb_deregister_callback(NEBCALLBACK_HOST_STATUS_DATA, id2sc_handle_data);
	neb_deregister_callback(NEBCALLBACK_PROGRAM_STATUS_DATA, id2sc_handle_data);
	neb_deregister_callback(NEBCALLBACK_STATE_CHANGE_DATA, id2sc_handle_data);

	/* log a message to the Icinga log file */
	snprintf(temp_buffer, sizeof(temp_buffer) - 1, "id2sc: shutdown completed\n");
	temp_buffer[sizeof(temp_buffer)-1] = '\x0';
	write_to_all_logs(temp_buffer, NSLOG_INFO_MESSAGE);

	ConnectionPool_free(&pool);
	URL_free(&url_t);

	return 0;
}


/* gets called every X minutes by an event in the scheduling queue */
void id2sc_reminder_message(char *message) {
	char temp_buffer[MAX_BUFLEN];

	/* log a message to the Icinga log file */
	snprintf(temp_buffer, sizeof(temp_buffer) - 1, "id2sc: I'm still here! %s", message);
	temp_buffer[sizeof(temp_buffer)-1] = '\x0';
	write_to_all_logs(temp_buffer, NSLOG_INFO_MESSAGE);

	return;
}


/* handle data from Icinga daemon */
int id2sc_handle_data(int event_type, void *data) {
	nebstruct_aggregated_status_data *agsdata = NULL;
	nebstruct_service_status_data *ssdata = NULL;
	nebstruct_host_status_data *hsdata = NULL;
	nebstruct_program_status_data *psdata = NULL;
	nebstruct_statechange_data *schangedata = NULL;
	service *temp_service = NULL;
	host *temp_host = NULL;
	char temp_buffer[8192];
	char *es[9];
	double retry_interval = 0.0;
	int last_state = -1;
	int last_hard_state = -1;
	ResultSet_T r;
//	int x = 0;
//	customvariablesmember *temp_customvar = NULL;

	/* what type of event/data do we have? */
	switch (event_type) {

	case NEBCALLBACK_AGGREGATED_STATUS_DATA:

		if ((agsdata = (nebstruct_aggregated_status_data *)data)) {

			snprintf(temp_buffer, sizeof(temp_buffer) - 1, "AGGREGATED_STATUS: %d:%d:%d\n",
			    agsdata->type,
			    agsdata->flags,
			    agsdata->attr
			);
			temp_buffer[sizeof(temp_buffer)-1] = '\x0';
			id2sc_write_to_log(temp_buffer);
		}

		con = ConnectionPool_getConnection(pool);
		r = Connection_executeQuery(con, "select * from info_system");
		while (ResultSet_next(r)) {
		    snprintf(temp_buffer, sizeof(temp_buffer) - 1, "SQL: %s\n", ResultSet_getString(r, 1));
		    temp_buffer[sizeof(temp_buffer)-1] = '\x0';
		    id2sc_write_to_log(temp_buffer);
		}
		Connection_close(con);

		break;

	case NEBCALLBACK_SERVICE_STATUS_DATA:

		if ((ssdata = (nebstruct_service_status_data *)data)) {
		    temp_service = (service *)ssdata->object_ptr;

		    es[0] = escape_buffer(temp_service->host_name);
		    es[1] = escape_buffer(temp_service->description);
		    es[2] = escape_buffer(temp_service->plugin_output);
		    es[3] = escape_buffer(temp_service->long_plugin_output);
		    es[4] = escape_buffer(temp_service->perf_data);
		    es[5] = escape_buffer(temp_service->event_handler);
		    es[6] = escape_buffer(temp_service->service_check_command);
		    es[7] = escape_buffer(temp_service->check_period);

		    if(es[3] != NULL) {
			if(strlen(es[3]) > MAX_TEXT_LEN) {
			    es[3][MAX_TEXT_LEN] = '\0';
			}
		    }

		    if(es[4] != NULL) {
			if(strlen(es[4]) > MAX_TEXT_LEN) {
			    es[4][MAX_TEXT_LEN] = '\0';
			}
		    }

		    snprintf(temp_buffer, MAX_BUFLEN - 1
		         , "SERVICE_STATUS: %d:%d:%d:%ld:%ld:%s:%s:%s:%s:%s:%d:%d:%d:%d:%d:%lu:%lu:%d:%lu:%lu:%d:%lu:%lu:%lu:%lu:%d:%lu:%lu:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%.5lf:%.5lf:%.5lf:%d:%d:%d:%d:%lu:%s:%s:%lf:%lf:%s\n"
		         , ssdata->type
		         , ssdata->flags
		         , ssdata->attr
		         , ssdata->timestamp.tv_sec
		         , ssdata->timestamp.tv_usec
		         , (es[0] == NULL) ? "" : es[0]
		         , (es[1] == NULL) ? "" : es[1]
		         , (es[2] == NULL) ? "" : es[2]
		         , (es[3] == NULL) ? "" : es[3]
		         , (es[4] == NULL) ? "" : es[4]
		         , temp_service->current_state
		         , temp_service->has_been_checked
		         , temp_service->should_be_scheduled
		         , temp_service->current_attempt
		         , temp_service->max_attempts
		         , (unsigned long)temp_service->last_check
		         , (unsigned long)temp_service->next_check
		         , temp_service->check_type
		         , (unsigned long)temp_service->last_state_change
		         , (unsigned long)temp_service->last_hard_state_change
		         , temp_service->last_hard_state
		         , (unsigned long)temp_service->last_time_ok
		         , (unsigned long)temp_service->last_time_warning
		         , (unsigned long)temp_service->last_time_unknown
		         , (unsigned long)temp_service->last_time_critical
		         , temp_service->state_type
		         , (unsigned long)temp_service->last_notification
		         , (unsigned long)temp_service->next_notification
		         , temp_service->no_more_notifications
		         , temp_service->notifications_enabled
		         , temp_service->problem_has_been_acknowledged
		         , temp_service->acknowledgement_type
		         , temp_service->current_notification_number
		         , temp_service->accept_passive_service_checks
		         , temp_service->event_handler_enabled
		         , temp_service->checks_enabled
		         , temp_service->flap_detection_enabled
		         , temp_service->is_flapping
		         , temp_service->percent_state_change
		         , temp_service->latency
		         , temp_service->execution_time
		         , temp_service->scheduled_downtime_depth
		         , temp_service->failure_prediction_enabled
		         , temp_service->process_performance_data
		         , temp_service->obsess_over_service
		         , temp_service->modified_attributes
		         , (es[5] == NULL) ? "" : es[5]
		         , (es[6] == NULL) ? "" : es[6]
		         , (double)temp_service->check_interval
		         , (double)temp_service->retry_interval
		         , (es[7] == NULL) ? "" : es[7]
		        );

		    temp_buffer[sizeof(temp_buffer)-1] = '\x0';

		    /* dump customvars status */
/*		    if (dump_customvar_status == IDO_TRUE) {
			for (temp_customvar = temp_service->custom_variables; temp_customvar != NULL; temp_customvar = temp_customvar->next) {

			    for (x = 0; x < 2; x++) {
				free(es[x]);
				es[x] = NULL;
			    }

			    es[0] = id2sc_escape_buffer(temp_customvar->variable_name);
			    es[1] = id2sc_escape_buffer(temp_customvar->variable_value);

			    snprintf(temp_buffer, MAX_BUFLEN - 1
				 , "%d=%s:%d:%s\n"
				 , IDO_DATA_CUSTOMVARIABLESTATUS
				 , (es[0] == NULL) ? "" : es[0]
				 , temp_customvar->has_been_modified
				 , (es[1] == NULL) ? "" : es[1]
			    );

			    temp_buffer[sizeof(temp_buffer)-1] = '\x0';
			}
		    }

		    snprintf(temp_buffer, MAX_BUFLEN - 1
			 , "%d\n\n"
			 , IDO_API_ENDDATA
		    );

		    temp_buffer[sizeof(temp_buffer)-1] = '\x0';
*/
		    id2sc_write_to_log(temp_buffer);

		}

		con = ConnectionPool_getConnection(pool);
		r = Connection_executeQuery(con, "select * from info_system");
		while (ResultSet_next(r)) {
		    snprintf(temp_buffer, sizeof(temp_buffer) - 1, "SQL: %s\n", ResultSet_getString(r, 1));
		    temp_buffer[sizeof(temp_buffer)-1] = '\x0';
		    id2sc_write_to_log(temp_buffer);
		}
		Connection_close(con);

		break;

	case NEBCALLBACK_PROGRAM_STATUS_DATA:

		if ((psdata = (nebstruct_program_status_data *)data)) {
		    es[0] = escape_buffer(psdata->global_host_event_handler);
		    es[1] = escape_buffer(psdata->global_service_event_handler);

		    snprintf(temp_buffer, MAX_BUFLEN - 1
		         , "PROGRAM_STATUS: %d:%d:%d:%ld:%ld:%lu:%d:%d:%lu:%lu:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%lu:%lu:%s:%s\n"
		         , psdata->type
		         , psdata->flags
		         , psdata->attr
		         , psdata->timestamp.tv_sec
		         , psdata->timestamp.tv_usec
		         , (unsigned long)psdata->program_start
		         , psdata->pid
		         , psdata->daemon_mode
		         , (unsigned long)psdata->last_command_check
		         , (unsigned long)psdata->last_log_rotation
		         , psdata->notifications_enabled
		         , psdata->active_service_checks_enabled
		         , psdata->passive_service_checks_enabled
		         , psdata->active_host_checks_enabled
		         , psdata->passive_host_checks_enabled
		         , psdata->event_handlers_enabled
		         , psdata->flap_detection_enabled
		         , psdata->failure_prediction_enabled
		         , psdata->process_performance_data
		         , psdata->obsess_over_hosts
		         , psdata->obsess_over_services
		         , psdata->modified_host_attributes
		         , psdata->modified_service_attributes
		         , (es[0] == NULL) ? "" : es[0]
		         , (es[1] == NULL) ? "" : es[1]
		        );

		    temp_buffer[sizeof(temp_buffer)-1] = '\x0';
		    id2sc_write_to_log(temp_buffer);
		}

		break;

	case NEBCALLBACK_HOST_STATUS_DATA:

		if ((hsdata = (nebstruct_host_status_data *)data)) {
		    temp_host = (host *)hsdata->object_ptr;

		    es[0] = escape_buffer(temp_host->name);
		    es[1] = escape_buffer(temp_host->plugin_output);
		    es[2] = escape_buffer(temp_host->long_plugin_output);
		    es[3] = escape_buffer(temp_host->perf_data);
		    es[4] = escape_buffer(temp_host->event_handler);
		    es[5] = escape_buffer(temp_host->host_check_command);
		    es[6] = escape_buffer(temp_host->check_period);

		    if(es[2] != NULL) {
			if(strlen(es[2]) > MAX_TEXT_LEN) {
			    es[2][MAX_TEXT_LEN] = '\0';
			}
		    }

		    if(es[3] != NULL) {
			if(strlen(es[3]) > MAX_TEXT_LEN) {
			    es[3][MAX_TEXT_LEN] = '\0';
			}
		    }

		    retry_interval = temp_host->retry_interval;

		    snprintf(temp_buffer, MAX_BUFLEN - 1
		         , "HOST_STATUS: %d:%d:%d:%ld:%ld:%s:%s:%s:%s:%d:%d:%d:%d:%d:%lu:%lu:%d:%lu:%lu:%d:%lu:%lu:%lu:%d:%lu:%lu:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%.5lf:%.5lf:%.5lf:%d:%d:%d:%d:%lu:%s:%s:%lf:%lf:%s\n"
		         , hsdata->type
		         , hsdata->flags
		         , hsdata->attr
		         , hsdata->timestamp.tv_sec
		         , hsdata->timestamp.tv_usec
		         , (es[0] == NULL) ? "" : es[0]
		         , (es[1] == NULL) ? "" : es[1]
		         , (es[2] == NULL) ? "" : es[2]
		         , (es[3] == NULL) ? "" : es[3]
		         , temp_host->current_state
		         , temp_host->has_been_checked
		         , temp_host->should_be_scheduled
		         , temp_host->current_attempt
		         , temp_host->max_attempts
		         , (unsigned long)temp_host->last_check
		         , (unsigned long)temp_host->next_check
		         , temp_host->check_type
		         , (unsigned long)temp_host->last_state_change
		         , (unsigned long)temp_host->last_hard_state_change
		         , temp_host->last_hard_state
		         , (unsigned long)temp_host->last_time_up
		         , (unsigned long)temp_host->last_time_down
		         , (unsigned long)temp_host->last_time_unreachable
		         , temp_host->state_type
		         , (unsigned long)temp_host->last_host_notification
		         , (unsigned long)temp_host->next_host_notification
		         , temp_host->no_more_notifications
		         , temp_host->notifications_enabled
		         , temp_host->problem_has_been_acknowledged
		         , temp_host->acknowledgement_type
		         , temp_host->current_notification_number
		         , temp_host->accept_passive_host_checks
		         , temp_host->event_handler_enabled
		         , temp_host->checks_enabled
		         , temp_host->flap_detection_enabled
		         , temp_host->is_flapping
		         , temp_host->percent_state_change
		         , temp_host->latency
		         , temp_host->execution_time
		         , temp_host->scheduled_downtime_depth
		         , temp_host->failure_prediction_enabled
		         , temp_host->process_performance_data
		         , temp_host->obsess_over_host
		         , temp_host->modified_attributes
		         , (es[4] == NULL) ? "" : es[4]
		         , (es[5] == NULL) ? "" : es[5]
		         , (double)temp_host->check_interval
		         , (double)retry_interval
		         , (es[6] == NULL) ? "" : es[6]
		        );

		    temp_buffer[sizeof(temp_buffer)-1] = '\x0';

		    /* dump customvars status */
/*		    if (dump_customvar_status == IDO_TRUE) {
			for (temp_customvar = temp_host->custom_variables; temp_customvar != NULL; temp_customvar = temp_customvar->next) {

			    for (x = 0; x < 2; x++) {
				free(es[x]);
				es[x] = NULL;
			    }

			    es[0] = escape_buffer(temp_customvar->variable_name);
			    es[1] = escape_buffer(temp_customvar->variable_value);

			    snprintf(temp_buffer, ID2SC_MAX_BUFLEN - 1
			         , "%d=%s:%d:%s\n"
			         , IDO_DATA_CUSTOMVARIABLESTATUS
			         , (es[0] == NULL) ? "" : es[0]
			         , temp_customvar->has_been_modified
			         , (es[1] == NULL) ? "" : es[1]
			        );

			    temp_buffer[sizeof(temp_buffer)-1] = '\x0';
			}
		    }

		    snprintf(temp_buffer, MAX_BUFLEN - 1
		         , "%d\n\n"
		         , IDO_API_ENDDATA
		        );

		    temp_buffer[sizeof(temp_buffer)-1] = '\x0';
*/		
		    id2sc_write_to_log(temp_buffer);
		}
		
		break;

	case NEBCALLBACK_STATE_CHANGE_DATA:

		if((schangedata = (nebstruct_statechange_data *)data)) {

		    /* get the last state info */
		    if (schangedata->service_description == NULL) {
			temp_host = (host *)schangedata->object_ptr;
			last_state = temp_host->last_state;
			last_hard_state = temp_host->last_hard_state;
		    } else {
			temp_service = (service *)schangedata->object_ptr;
			last_state = temp_service->last_state;
			last_hard_state = temp_service->last_hard_state;
		    }

		    es[0] = escape_buffer(schangedata->host_name);
		    es[1] = escape_buffer(schangedata->service_description);
		    es[2] = escape_buffer(schangedata->output);

		    snprintf(temp_buffer, MAX_BUFLEN - 1
		         , "STATE_CHANGE: %d:%d:%d:%ld:%ld:%d:%s:%s:%d:%d:%d:%d:%d:%d:%d:%s\n"
		         , schangedata->type
		         , schangedata->flags
		         , schangedata->attr
		         , schangedata->timestamp.tv_sec
		         , schangedata->timestamp.tv_usec
		         , schangedata->statechange_type
		         , (es[0] == NULL) ? "" : es[0]
		         , (es[1] == NULL) ? "" : es[1]
		         , TRUE
		         , schangedata->state
		         , schangedata->state_type
		         , schangedata->current_attempt
		         , schangedata->max_attempts
		         , last_state
		         , last_hard_state
		         , es[2]
		        );

		    temp_buffer[sizeof(temp_buffer)-1] = '\x0';
		
		    id2sc_write_to_log(temp_buffer);
		}

		break;
	default:
		break;
	}

	return 0;
}

/************************ HELPER FUNCTIONS ************************/
/* writing to file */
int id2sc_write_to_log(char *message) {
	FILE *file;
	file = fopen(lgfile,"a+");
	fprintf(file, "[%d] %s", (int)time(NULL), message);
	fclose(file);
	return 0;
}

/* Error Message */
int error_message(char *message) {
	write_to_all_logs("#### ERROR ####", NSLOG_INFO_MESSAGE);
	write_to_all_logs("", NSLOG_INFO_MESSAGE);
	write_to_all_logs(message, NSLOG_INFO_MESSAGE);
	write_to_all_logs("", NSLOG_INFO_MESSAGE);
	write_to_all_logs("#### ERROR ####", NSLOG_INFO_MESSAGE);
	return 0;
}

/************************ STRING FUNCTIONS ************************/
/* strip newline, carriage return, and tab characters from beginning and end of a string */
void strip(char *buffer) {
	register int x = 0;
	register int y = 0;
	register int z = 0;

	if (buffer == NULL || buffer[0] == '\x0')
	    return;

	/* strip end of string */
	y = (int)strlen(buffer);
	for (x = y - 1; x >= 0; x--) {
	    if (buffer[x] == ' ' || buffer[x] == '\n' || buffer[x] == '\r' || buffer[x] == '\t' || buffer[x] == 13)
		buffer[x] = '\x0';
	    else
		break;
	}
	/* save last position for later... */
	z = x;

	/* strip beginning of string (by shifting) */
	for (x = 0;; x++) {
	    if (buffer[x] == ' ' || buffer[x] == '\n' || buffer[x] == '\r' || buffer[x] == '\t' || buffer[x] == 13)
		continue;
	    else
		break;
	}
	if (x > 0) {
	    /* new length of the string after we stripped the end */
	    y = z + 1;

	    /* shift chars towards beginning of string to remove leading whitespace */
	    for (z = x; z < y; z++)
		buffer[z-x] = buffer[z];
		buffer[y-x] = '\x0';
	}

	return;
}

/* strip newline and carriage return characters from end of a string */
void strip_buffer(char *buffer) {
	register int x;
	register int y;

	if (buffer == NULL || buffer[0] == '\x0')
	    return;

	/* strip end of string */
	y = (int)strlen(buffer);
	for (x = y - 1; x >= 0; x--) {
	    if (buffer[x] == '\n' || buffer[x] == '\r' || buffer[x] == 13)
		buffer[x] = '\x0';
	    else
		break;
	}

	return;
}

/* escape special characters in string */
char *escape_buffer(char *buffer) {
	char *newbuf;
	register int x = 0;
	register int y = 0;
	register int len = 0;

	if (buffer == NULL)
		return NULL;

	/* allocate memory for escaped string */
	if ((newbuf = (char *)malloc((strlen(buffer) * 2) + 1)) == NULL)
		return NULL;

	/* initialize string */
	newbuf[0] = '\x0';

	len = (int)strlen(buffer);
	for (x = 0; x < len; x++) {
		if (buffer[x] == '\t') {
			newbuf[y++] = '\\';
			newbuf[y++] = 't';
		} else if (buffer[x] == '\r') {
			newbuf[y++] = '\\';
			newbuf[y++] = 'r';
		} else if (buffer[x] == '\n') {
			newbuf[y++] = '\\';
			newbuf[y++] = 'n';
		} else if (buffer[x] == '\\') {
			newbuf[y++] = '\\';
			newbuf[y++] = '\\';
		} else
			newbuf[y++] = buffer[x];
	}

	/* terminate new string */
	newbuf[y++] = '\x0';

	return newbuf;
}

/* unescape special characters in string */
char *unescape_buffer(char *buffer) {
	register int x = 0;
	register int y = 0;
	register int len = 0;

	if (buffer == NULL)
	    return NULL;

	len = (int)strlen(buffer);
	for (x = 0; x < len; x++) {
	    if (buffer[x] == '\\') {
		if (buffer[x+1] == '\t')
		    buffer[y++] = '\t';
		else if (buffer[x+1] == 'r')
		    buffer[y++] = '\r';
		else if (buffer[x+1] == 'n')
		    buffer[y++] = '\n';
		else if (buffer[x+1] == '\\')
		    buffer[y++] = '\\';
		else
		    buffer[y++] = buffer[x+1];
		    x++;
	    } else
		buffer[y++] = buffer[x];
	}

	/* terminate string */
	buffer[y++] = '\x0';

	return buffer;
}


/***************************** CONFIG FUNCTIONS *******************************/
/* process arguments that were passed to the module at startup */
int process_module_args(char *args) {
	char *ptr = NULL;
	char **arglist = NULL;
	char **newarglist = NULL;
	int argcount = 0;
	int memblocks = 64;
	int arg = 0;

	if (args == NULL)
	    return IDO_OK;

	/* get all the var/val argument pairs */

	/* allocate some memory */
	if ((arglist = (char **)malloc(memblocks * sizeof(char **))) == NULL)
	    return IDO_ERROR;

	/* process all args */
	ptr = strtok(args, ",");
        while (ptr) {
	    /* save the argument */
	    arglist[argcount++] = strdup(ptr);

	    /* allocate more memory if needed */
	    if (!(argcount % memblocks)) {
		if ((newarglist = (char **)realloc(arglist, (argcount + memblocks) * sizeof(char **))) == NULL) {
		    for (arg = 0; arg < argcount; arg++) {
			free(arglist[argcount]);
			free(arglist);
			return IDO_ERROR;
		    }
		} else {
		    arglist = newarglist;
		}
	    }
		ptr = strtok(NULL, ",");
	}

	/* terminate the arg list */
	arglist[argcount] = '\x0';

	/* process each argument */
	for (arg = 0; arg < argcount; arg++) {
//	    write_to_all_logs(arglist[arg], NSLOG_INFO_MESSAGE);
	    if (process_config_var(arglist[arg]) == IDO_ERROR) {
		for (arg = 0; arg < argcount; arg++) {
		    free(arglist[arg]);
		    free(arglist);
		    return IDO_ERROR;
		}
	    }
        }

	/* free allocated memory */
	for (arg = 0; arg < argcount; arg++) {
	    free(arglist[arg]);
	    free(arglist);
	}

	return IDO_OK;
}


/* process all config vars in a file */
int process_config_file(char *filename) {
	ido_mmapfile *thefile = NULL;
	char *buf = NULL;
	char temp_buffer[MAX_BUFLEN];
	int result = IDO_OK;

	/* open the file */
	if ((thefile = ido_mmap_fopen(filename)) == NULL) {
	    snprintf(temp_buffer, sizeof(temp_buffer) - 1, "id2sc: Unable to open configuration file %s: %s\n", filename, strerror(errno));
	    temp_buffer[sizeof(temp_buffer)-1] = '\x0';
	    error_message(temp_buffer);
	    return IDO_ERROR;
	}

	/* process each line of the file */
	while ((buf = ido_mmap_fgets(thefile))) {

	    /* skip comments */
	    if (buf[0] == '#') {
		free(buf);
		continue;
	    }

	    /* skip blank lines */
	    if (!strcmp(buf, "")) {
		free(buf);
		continue;
	    }

	    /* process the variable */
	    result = process_config_var(buf);

	    /* free memory */
	    free(buf);

	    if (result != IDO_OK)
		break;
        }

	/* close the file */
	ido_mmap_fclose(thefile);

	return result;
}


/* process a single module config variable */
int process_config_var(char *arg) {
	char *var = NULL;
	char *val = NULL;
	char temp_buffer[MAX_BUFLEN];

	/* split var/val */
	var = strtok(arg, "=");
	val = strtok(NULL, "\n");

	/* skip incomplete var/val pairs */
	if (var == NULL || val == NULL)
	    return IDO_OK;

	/* strip var/val */
	strip(var);
	strip(val);

	/* process the variable... */

	if (!strcmp(var, "config_file")) {
	    return process_config_file(val);
	} else if (!strcmp(var, "pg.url")) {
	    pgurl = strdup(val);
	    snprintf(temp_buffer, sizeof(temp_buffer) - 1, "id2sc: pg.url = '%s'\n", pgurl);
	    temp_buffer[sizeof(temp_buffer)-1] = '\x0';
	    write_to_all_logs(temp_buffer, NSLOG_INFO_MESSAGE);
	} else if (!strcmp(var, "id.name")) {
	    idname = strdup(val);
	    snprintf(temp_buffer, sizeof(temp_buffer) - 1, "id2sc: id.name = '%s'\n", idname);
	    temp_buffer[sizeof(temp_buffer)-1] = '\x0';
	    write_to_all_logs(temp_buffer, NSLOG_INFO_MESSAGE);
	} else if (!strcmp(var, "lg.file")) {
	    lgfile = strdup(val);
	    snprintf(temp_buffer, sizeof(temp_buffer) - 1, "id2sc: lg.file = '%s'\n", lgfile);
	    temp_buffer[sizeof(temp_buffer)-1] = '\x0';
	    write_to_all_logs(temp_buffer, NSLOG_INFO_MESSAGE);
	} else {
	    /* log an error message to the Icinga log file */
	    snprintf(temp_buffer, sizeof(temp_buffer) - 1, "id2sc: ERROR - Unknown config file variable '%s'.\n", var);
	    temp_buffer[sizeof(temp_buffer)-1] = '\x0';
	    error_message(temp_buffer);
	    return IDO_ERROR;
	}

	return IDO_OK;
}

/****** MMAP()'ED FILE FUNCTIONS ******************************/
/* open a file read-only via mmap() */
ido_mmapfile *ido_mmap_fopen(char *filename) {
	ido_mmapfile *new_mmapfile;
	int fd;
	void *mmap_buf;
	struct stat statbuf;
	int mode = O_RDONLY;

	/* allocate memory */
	if ((new_mmapfile = (ido_mmapfile *)malloc(sizeof(ido_mmapfile))) == NULL)
	    return NULL;

	/* open the file */
	if ((fd = open(filename, mode)) == -1) {
	    free(new_mmapfile);
	    return NULL;
	}

	/* get file info */
	if ((fstat(fd, &statbuf)) == -1) {
	    close(fd);
	    free(new_mmapfile);
	    return NULL;
	}

	/* mmap() the file */
	if ((mmap_buf = (void *)mmap(0, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
	    close(fd);
	    free(new_mmapfile);
	    return NULL;
	}

	/* populate struct info for later use */
	/*new_mmapfile->path=strdup(filename);*/
	new_mmapfile->path = NULL;
	new_mmapfile->fd = fd;
	new_mmapfile->file_size = (unsigned long)(statbuf.st_size);
	new_mmapfile->current_position = 0L;
	new_mmapfile->current_line = 0L;
	new_mmapfile->mmap_buf = mmap_buf;

	return new_mmapfile;
}


/* close a file originally opened via mmap() */
int ido_mmap_fclose(ido_mmapfile *temp_mmapfile) {

	if (temp_mmapfile == NULL)
	    return IDO_ERROR;

	/* un-mmap() the file */
	munmap(temp_mmapfile->mmap_buf, temp_mmapfile->file_size);

	/* close the file */
	close(temp_mmapfile->fd);

	/* free memory */
	if (temp_mmapfile->path != NULL)
	    free(temp_mmapfile->path);
	free(temp_mmapfile);

	return IDO_OK;
}


/* gets one line of input from an mmap()'ed file */
char *ido_mmap_fgets(ido_mmapfile *temp_mmapfile) {
	char *buf = NULL;
	unsigned long x = 0L;
	int len = 0;

	if (temp_mmapfile == NULL)
	    return NULL;

	/* we've reached the end of the file */
	if (temp_mmapfile->current_position >= temp_mmapfile->file_size)
	    return NULL;

	/* find the end of the string (or buffer) */
	for (x = temp_mmapfile->current_position; x < temp_mmapfile->file_size; x++) {
	    if (*((char *)(temp_mmapfile->mmap_buf) + x) == '\n') {
		x++;
		break;
	    }
	}

	/* calculate length of line we just read */
	len = (int)(x - temp_mmapfile->current_position);

	/* allocate memory for the new line */
	if ((buf = (char *)malloc(len + 1)) == NULL)
	    return NULL;

	/* copy string to newly allocated memory and terminate the string */
	memcpy(buf, ((char *)(temp_mmapfile->mmap_buf) + temp_mmapfile->current_position), len);
	buf[len] = '\x0';

	/* update the current position */
	temp_mmapfile->current_position = x;

	/* increment the current line */
	temp_mmapfile->current_line++;

	return buf;
}

/****** ZDB Functions ******************************/
/*  */

