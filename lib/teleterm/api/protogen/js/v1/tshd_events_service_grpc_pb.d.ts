// package: teleport.terminal.v1
// file: v1/tshd_events_service.proto

/* tslint:disable */
/* eslint-disable */

import * as grpc from "grpc";
import * as v1_tshd_events_service_pb from "../v1/tshd_events_service_pb";

interface ITshdEventsServiceService extends grpc.ServiceDefinition<grpc.UntypedServiceImplementation> {
    reloginRequired: ITshdEventsServiceService_IReloginRequired;
}

interface ITshdEventsServiceService_IReloginRequired extends grpc.MethodDefinition<v1_tshd_events_service_pb.ReloginRequiredRequest, v1_tshd_events_service_pb.ReloginRequiredResponse> {
    path: "/teleport.terminal.v1.TshdEventsService/ReloginRequired";
    requestStream: false;
    responseStream: false;
    requestSerialize: grpc.serialize<v1_tshd_events_service_pb.ReloginRequiredRequest>;
    requestDeserialize: grpc.deserialize<v1_tshd_events_service_pb.ReloginRequiredRequest>;
    responseSerialize: grpc.serialize<v1_tshd_events_service_pb.ReloginRequiredResponse>;
    responseDeserialize: grpc.deserialize<v1_tshd_events_service_pb.ReloginRequiredResponse>;
}

export const TshdEventsServiceService: ITshdEventsServiceService;

export interface ITshdEventsServiceServer {
    reloginRequired: grpc.handleUnaryCall<v1_tshd_events_service_pb.ReloginRequiredRequest, v1_tshd_events_service_pb.ReloginRequiredResponse>;
}

export interface ITshdEventsServiceClient {
    reloginRequired(request: v1_tshd_events_service_pb.ReloginRequiredRequest, callback: (error: grpc.ServiceError | null, response: v1_tshd_events_service_pb.ReloginRequiredResponse) => void): grpc.ClientUnaryCall;
    reloginRequired(request: v1_tshd_events_service_pb.ReloginRequiredRequest, metadata: grpc.Metadata, callback: (error: grpc.ServiceError | null, response: v1_tshd_events_service_pb.ReloginRequiredResponse) => void): grpc.ClientUnaryCall;
    reloginRequired(request: v1_tshd_events_service_pb.ReloginRequiredRequest, metadata: grpc.Metadata, options: Partial<grpc.CallOptions>, callback: (error: grpc.ServiceError | null, response: v1_tshd_events_service_pb.ReloginRequiredResponse) => void): grpc.ClientUnaryCall;
}

export class TshdEventsServiceClient extends grpc.Client implements ITshdEventsServiceClient {
    constructor(address: string, credentials: grpc.ChannelCredentials, options?: object);
    public reloginRequired(request: v1_tshd_events_service_pb.ReloginRequiredRequest, callback: (error: grpc.ServiceError | null, response: v1_tshd_events_service_pb.ReloginRequiredResponse) => void): grpc.ClientUnaryCall;
    public reloginRequired(request: v1_tshd_events_service_pb.ReloginRequiredRequest, metadata: grpc.Metadata, callback: (error: grpc.ServiceError | null, response: v1_tshd_events_service_pb.ReloginRequiredResponse) => void): grpc.ClientUnaryCall;
    public reloginRequired(request: v1_tshd_events_service_pb.ReloginRequiredRequest, metadata: grpc.Metadata, options: Partial<grpc.CallOptions>, callback: (error: grpc.ServiceError | null, response: v1_tshd_events_service_pb.ReloginRequiredResponse) => void): grpc.ClientUnaryCall;
}
